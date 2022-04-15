import os

# TODO: Supressing error messages is undesirable. Remove this once CUDA is installed.
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import time
import numpy as np
import tensorflow as tf
from termcolor import colored
from datetime import timedelta
from cleverhans.tf2.attacks.fast_gradient_method import fast_gradient_method

from utils.embedding import Matrix
from utils.initializations import initialize
from utils.logs import print_score
from utils.os import code_section_hash, hash_bytes
from utils.statistics import byte_distribution
from utils.results import GradientAttackResults, FullAttackResults

TARGET_MALICIOUS = [[1.0]]
TARGET_BENIGN = [[0.0]]
MALICIOUS_THESHOLD = 0.50

def create_z_new(z, z_payload, file_size, payload_size):
    beg = z[0][:file_size]
    mid = z_payload[0][:payload_size]
    end = z[0][file_size+payload_size:]

    joined = tf.concat([beg, mid, end], 0)
    return tf.expand_dims(joined, 0, name=None)

def fgsm_append(
    sample,
    malconv,
    attack_config,
    payload_size
):
    time_start = time.perf_counter()

    attack_results = GradientAttackResults()
    attack_results.payload_size = payload_size

    if sample.x_len + payload_size > malconv.input_size:
        print('Unable to attack file. Input file with attached payload would exceed MalConv input size of 1MB.')
        attack_results.processable == False
        return attack_results

    # Add a payload to the file and then obtain the embedded representation
    x_payload = initialize(attack_config.initialization_method, payload_size, sample.benign)
    z = malconv.embed(sample.x)
    z_payload = malconv.embed(x_payload)
    z_new = create_z_new(z, z_payload, sample.x_len, payload_size)

    # Record the initial prediction when ran on the post-embedding portion of the model
    print(f'Running Fast Gradient Sign Method (FGSM):')
    y_hat = malconv.predict_embedded(z_new)
    print_score(y_hat, 'original', False, '   Embedded ')

    payload_hash_orig = hash_bytes(x_payload)
    payload_hash_embedded = hash_bytes(z_payload)
    print(f'   Payload hash (Original bytes): {payload_hash_orig}')
    print(f'   Payload hash (Original embedded): {payload_hash_embedded}')

    # Perform the adversarial gradient-based attack
    for i in range(attack_config.max_iterations):
        signed_grad = fast_gradient_method(
            malconv.embedding_space_model,
            z_new,
            attack_config.epsilon,
            norm=np.inf,
            y=attack_config.y_target,
            targeted=True,
            clip_min=-1,
            clip_max=1,
            loss_fn=tf.nn.sigmoid_cross_entropy_with_logits
        )
        z_new = tf.add(z_new, signed_grad)
        z_new = tf.clip_by_value(z_new, -1, 1)
        z_payload = tf.expand_dims(z_new[0][sample.x_len:sample.x_len+payload_size], 0)
        z_new = create_z_new(z, z_payload, sample.x_len, payload_size)

        y_hat = malconv.predict_embedded(z_new)
        attack_results.iterations = i+1
        print_score(y_hat, f'iteration {attack_results.iterations}', False, '   Embedded ')

        # Bail out early when the desired score is reached
        if attack_config.y_target == TARGET_MALICIOUS and y_hat > 0.99:
            if attack_config.verbose:
                print('   Stopping early (Embedded bytes >99% malicious)')
            break
        if attack_config.y_target == TARGET_BENIGN and y_hat < 0.01:
            if attack_config.verbose:
                print('   Stopping early (Embedded bytes < 1%) malicious')
            break
    
    # Success in the embedding stage may not mean success after final reconstruction
    attack_results.z_new_embermalconv_score = y_hat
    success = malconv.determine_success(attack_config.y_target, y_hat)
    result = 'successful' if success == True else 'failed'
    print(f'   Gradient attack {result}.')

    # Reconstruction phase
    # Map backwards through the embedding layer to produce the final result x_new
    reconstruction_time_start = time.perf_counter()
    emb_matrix = Matrix(malconv)
    embedded_payload = z_payload[0][:payload_size]
    if attack_config.reconstuct_full_file:
        # Psuedocode in Kreuk et al. (2019) seems to call for looping over the entire file
        # This is incredibly slow, so avoid this if possible.
        # Remove the ability to do this in a future release
        embeddings = z_new[0]
        attack_results.x_new = emb_matrix.reconstruction(embeddings, attack_config.reconstruct_kdtrees, attack_config.reconstruct_parallel)
        payload = attack_results.x_new[sample.x_len:len(z_new)]
    else:
        payload = emb_matrix.reconstruction(embedded_payload, attack_config.reconstruct_kdtrees, attack_config.reconstruct_parallel)
        attack_results.x_new = sample.x[:sample.x_len] + payload

    # Record information about resulting binary
    attack_results.x_new_hash = hash_bytes(attack_results.x_new)
    attack_results.x_new_code_hash = code_section_hash(attack_results.x_new)[0]
    attack_results.x_new_len = len(attack_results.x_new)
    attack_results.payload_byte_distribution = byte_distribution(payload)
    attack_results.reconstruction_duration = timedelta(seconds=time.perf_counter()-reconstruction_time_start)

    payload_hash_embedded_new = hash_bytes(embedded_payload)
    print(f'   Payload hash (Perturbed embedded): {payload_hash_embedded_new}')

    payload_hash_reconstructed = hash_bytes(payload)
    print(f'   Payload hash (Reconstructed bytes): {payload_hash_reconstructed}')

    # Determine final success
    attack_results.x_new_embermalconv_score = malconv.predict(attack_results.x_new)
    attack_results.evades_malconv = malconv.determine_success(attack_config.y_target, attack_results.x_new_embermalconv_score)
    attack_results.evades_predetection = sample.x_code_hash != attack_results.x_new_code_hash
    print(f'   Evades MalConv: {attack_results.evades_malconv}')

    # Record attack duration
    attack_results.duration = timedelta(seconds=time.perf_counter()-time_start)
    attack_results.attack_performed = True

    return attack_results

def has_better_score(result, best_result, y_target):
    best_score = best_result.x_new_embermalconv_score
    new_score = result.x_new_embermalconv_score
    if y_target == TARGET_MALICIOUS and new_score > best_score:
        return True
    if y_target == TARGET_BENIGN and new_score < best_score:
        return True
    return False

# Performs the FGSM Append attack multiple times, slowly increasing the
# payload size until a succesful evasion is achieved. This results in a
# smaller payload at the expense of additional compute time.
# A "binary search" strategy may not necessarly be better, as in some
# cases *decreasing* the payload size after a failure can allow the attack
# to succeed.
def fgsm_append_optimal(
    sample,
    malconv,
    attack_config
):
    time_start = time.perf_counter()
    full_results = sample.results
    print(f'[FGSM Overlay Attack] Performing search for optimal payload size')

    if sample.x_len > malconv.input_size:
        print('Unable to attack file. Input file exceeds MalConv input size of 1MB.')
        return full_results
    remaining_overlay_space = malconv.input_size - sample.x_len

    maximum_payload_size = attack_config.payload_size
    if remaining_overlay_space < maximum_payload_size:
        maximum_payload_size = remaining_overlay_space

    candidate_payload_size = 50
    while candidate_payload_size <= maximum_payload_size:
        print(colored(f'[FGSM Overlay Attack] Payload size: {candidate_payload_size} bytes', 'blue', 'on_green'))
        result = fgsm_append(sample, malconv, attack_config, candidate_payload_size)
        full_results.attack_count += 1
        full_results.combined_iterations += result.iterations
        full_results.combined_reconstruction_duration += result.reconstruction_duration

        if has_better_score(result, full_results.best_result, attack_config.y_target):
            full_results.best_result = result

        if result.evades_malconv:
            print(f'Smallest successful payload size found: {candidate_payload_size}')
            break

        candidate_payload_size += 50

    if full_results.best_result is None or full_results.best_result.evades_malconv == False:
        print(f'All attacks failed.')

    full_results.combined_duration = timedelta(seconds=time.perf_counter()-time_start)
    return full_results