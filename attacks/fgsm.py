import os
import time
from datetime import timedelta

# TODO: Supressing error messages is undesirable. Remove this once CUDA is installed.
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import numpy as np
import tensorflow as tf
from termcolor import colored
from cleverhans.tf2.attacks.fast_gradient_method import fast_gradient_method

from utils.embedding import Matrix
from utils.initializations import initialize
from utils.logs import print_score
from utils.os import hash_bytes
from utils.statistics import byte_distribution

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
    attack_config
):
    if sample.processable == False:
        print('Unable to perturb file. Input file with attached payload exceeds MalConv input size of 1MB.')
        return sample

    time_start = time.perf_counter()

    # Add a payload to the file and then obtain the embedded representation
    x_payload = initialize(sample.initialization_method, sample.payload_size, sample.input_benign)
    z = malconv.embed(sample.x)
    z_payload = malconv.embed(x_payload)
    z_new = create_z_new(z, z_payload, sample.x_len, sample.payload_size)

    # Record the initial prediction when ran on the post-embedding portion of the model
    print(f'Running Fast Gradient Sign Method (FGSM):')
    y_hat = malconv.predict_embedded(z_new)
    print_score(y_hat, 'original', False, '   Embedded ')

    payload_hash_orig = hash_bytes(x_payload)
    payload_hash_embedded = hash_bytes(z_payload)
    print(f'   Payload hash (Original bytes): {payload_hash_orig}')
    print(f'   Payload hash (Original embedded): {payload_hash_embedded}')

    # Perform the adversarial gradient-based attack
    for i in range(sample.max_iterations):
        signed_grad = fast_gradient_method(
            malconv.embedding_space_model,
            z_new,
            sample.epsilon,
            norm=np.inf,
            y=sample.y_target,
            targeted=True,
            clip_min=-1,
            clip_max=1,
            loss_fn=tf.nn.sigmoid_cross_entropy_with_logits
        )
        z_new = tf.add(z_new, signed_grad)
        z_new = tf.clip_by_value(z_new, -1, 1)
        z_payload = tf.expand_dims(z_new[0][sample.x_len:sample.x_len+sample.payload_size], 0)
        z_new = create_z_new(z, z_payload, sample.x_len, sample.payload_size)

        y_hat = malconv.predict_embedded(z_new)
        sample.iterations = i+1
        print_score(y_hat, f'iteration {sample.iterations}', False, '   Embedded ')

        # Bail out early when the desired score is reached
        if sample.y_target == TARGET_MALICIOUS and y_hat > 0.99:
            if attack_config.verbose:
                print('   Stopping early (Embedded bytes >99% malicious)')
            break
        if sample.y_target == TARGET_BENIGN and y_hat < 0.01:
            if attack_config.verbose:
                print('   Stopping early (Embedded bytes < 1%) malicious')
            break
    
    # Success in the embedding stage may not mean success after final reconstruction
    sample.z_new_embermalconv_score = y_hat
    success = malconv.determine_success(sample.y_target, y_hat)
    result = 'successful' if success == True else 'failed'
    print(f'   Gradient attack {result}.')

    # Reconstruction phase
    # Map backwards through the embedding layer to produce the final result x_new
    reconstruction_time_start = time.perf_counter()
    emb_matrix = Matrix(malconv)
    embedded_payload = z_payload[0][:sample.payload_size]
    if attack_config.reconstuct_full_file:
        # Original algorithm in Kreuk et al. (2019) calls for looping over full file
        # This is incredibly slow, so avoid this if possible.
        full_length = sample.x_len + sample.payload_size
        embeddings = z_new[0] # [:full_length]
        sample.x_new = emb_matrix.reconstruction(embeddings, attack_config.reconstruct_kdtrees, attack_config.reconstruct_parallel)
        payload = sample.x_new[sample.x_len:len(z_new)]
    else:
        payload = emb_matrix.reconstruction(embedded_payload, attack_config.reconstruct_kdtrees, attack_config.reconstruct_parallel)
        sample.x_new = sample.x[:sample.x_len] + payload
    sample.x_new_len = len(sample.x_new)
    sample.payload_byte_distribution = byte_distribution(payload)
    sample.reconstruction_duration = timedelta(seconds=time.perf_counter()-reconstruction_time_start)

    payload_hash_embedded_new = hash_bytes(embedded_payload)
    print(f'   Payload hash (Perturbed embedded): {payload_hash_embedded_new}')

    payload_hash_reconstructed = hash_bytes(payload)
    print(f'   Payload hash (Reconstructed bytes): {payload_hash_reconstructed}')

    # Record attack duration
    sample.duration = timedelta(seconds=time.perf_counter()-time_start)

    return sample