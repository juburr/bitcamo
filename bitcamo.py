#!/usr/bin/env python3

import argparse
import os
import numpy as np

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import colorama
from termcolor import colored

from attacks.config import AttackConfig
from attacks.fgsm import fgsm_append, fgsm_append_optimal
from attacks.predetection import bypass_predetection
from models.malconv import MalConv, KERNEL_SIZE, TARGET_BENIGN, TARGET_MALICIOUS
from utils.os import code_section_hash, exit, validate_output_directory
from utils.sample import Sample
from utils.logs import color_success, format_timedelta, print_error, print_score
from utils.results import FinalResults

# Colorama allows termcolor to work with Windows. More importantly though,
# when you pipe output to a file in Linux, it won't save the weird control characters.
colorama.init()

def pre_attack(sample, malconv, attack_config):
    print(f'Original file hash: {sample.x_hash}')
    print(f'Original base code section hash: {sample.x_code_hash} ({sample.x_code_section_name})')

    if attack_config.payload_size == 0:
        attack_config.payload_size = KERNEL_SIZE + (KERNEL_SIZE - np.mod(len(sample.x), KERNEL_SIZE))

    # Record the initial prediction
    sample.x_embermalconv_score = malconv.predict(sample.x)
    print_score(sample.x_embermalconv_score, 'Original Executable', attack_config.verbose, '')

    sample.results.initialize(sample)

    return sample

def post_attack(sample, attack_config):
    result = sample.results.best_result
    if result.processable == False:
        print_error('File could not be attacked. It may be too large.')
        return sample

    print_score(result.x_new_embermalconv_score, 'Modified Executable', attack_config.verbose, '')
    print(f'Modified file hash: {result.x_new_hash}')
    print(f'Modified base code section hash: {result.x_new_code_hash} ({sample.x_code_section_name})')
    print(f'Attack duration: {format_timedelta(sample.results.combined_duration)}')
    print('Results:')
    print('   Evades MalConv:', color_success(result.evades_malconv))
    if attack_config.evade_predetection:
        print('   Evades pre-detection mechanism:', color_success(result.evades_predetection))
    print('Perturbed executable path:')
    print(f'   Location: {sample.output_path}')

    sample.write()

    return sample

def attack(samples, attack_config):
    malconv = MalConv(attack_mode=True)
    count = 0
    for s in samples:
        count = count + 1

        print(colored(f'[{s.input_path}]', 'blue', 'on_yellow'))
        print(f'File {count} of {len(samples)}')
        s.read()

        print(colored('[Input]', 'magenta', 'on_cyan'))
        s = pre_attack(s, malconv, attack_config)

        print(colored('[Attack Phase]', 'magenta', 'on_cyan'))
        if malconv.evasion_achieved(s.x_embermalconv_score, attack_config.y_target) == False:
            if attack_config.optimize_payload_size:
                s.results = fgsm_append_optimal(s, malconv, attack_config)
            else:
                s.results.best_result = fgsm_append(s, malconv, attack_config, attack_config.payload_size)
                s.results.attack_count = 1
                s.results.combined_iterations = s.results.best_result.iterations
                s.results.combined_duration = s.results.best_result.duration
                s.results.combined_reconstruction_duration = s.results.best_result.reconstruction_duration
        else:
            print('   Original sample will already evade MalConv.')

        if attack_config.evade_predetection:
            print(f'Patching code section:')
            patched = False
            if s.results.best_result.x_new is not None:
                s.results.best_result.x_new, patched = bypass_predetection(s.results.best_result.x_new)
            print(f'   Attack evades pre-detection: {patched}')
            s.results.best_result.x_new_code_hash = code_section_hash(s.results.best_result.x_new)[0]
            s.results.best_result.evades_predetection = s.x_code_hash != s.results.best_result.x_new_code_hash

        print(colored('[Results]', 'magenta', 'on_cyan'))
        s = post_attack(s, attack_config)

        # Before moving on to the next sample, release memory such as the file's raw bytes
        s.free()
        print('\n')

    res = FinalResults(samples, attack_config)
    res.print()

def get_sample(filepath, output_dir, benign, overwrite_output):
    s = Sample(
            path=filepath,
            output_dir=output_dir,
            benign=benign,
            overwrite_output=overwrite_output,
        )
    if s.valid == False:
        exit(1)
    return s

def get_input_samples(input_filepath, output_dir, benign, overwrite_output):
    samples = []

    if os.path.exists(input_filepath) == False:
        print_error(f'Input path does not exist: {input_filepath}')
        exit(1)

    if os.path.isfile(input_filepath):
        s = get_sample(input_filepath, output_dir, benign, overwrite_output)
        samples.append(s)

    if os.path.isdir(input_filepath):
        if os.access(input_filepath, os.R_OK | os.X_OK) == False:
            print_error(f'Insufficient permission to access input directory: {input_filepath}')
            exit(1)

        print(f'Scanning for valid PE files in directory: {input_filepath}')
        files = os.listdir(input_filepath)
        for f in files:
            f = os.path.join(input_filepath, f)
            if os.path.isfile(f):
                s = get_sample(f, output_dir, benign, overwrite_output)
                samples.append(s)
        num_samples = len(samples)
        print(f'Found {num_samples} PE files.\n')

    return samples

def attack_config_from_program_args(args):
    cfg = AttackConfig()

    cfg.bengin_inputs = args.benign
    cfg.payload_size = args.payload_size
    cfg.initialization_method = args.initalization_method
    cfg.reconstuct_full_file = args.fullreconstruct
    cfg.reconstruct_parallel = args.parallel
    cfg.reconstruct_kdtrees = args.l2norm == False
    cfg.verbose = args.verbose
    cfg.evade_predetection = args.predetection
    cfg.optimize_payload_size = args.optimize_payload
    cfg.y_target = TARGET_MALICIOUS if args.benign else TARGET_BENIGN

    return cfg

def main():
    print('BitCamo\n')

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', help='increase output verbosity', action='store_true')
    parser.add_argument('-p', '--payload-size', type=int, help='payload size in bytes (optional)', default=900)
    parser.add_argument('--preserve', help='prevent overwrite of existing output file exists', action='store_true')
    parser.add_argument('-b', '--benign', help='input file is benign and target class is malicious', action='store_true')
    parser.add_argument('-o', '--output-dir', type=str, default='samples/output', help='directory to store the modified PE file(s)')
    parser.add_argument('-i', '--initalization-method', type=str, default='', help='payload initalization method to use. Options are random, psuedorandom, weighted, zeros, and ones.')
    parser.add_argument('-O', '--optimize-payload', help='attack until the minimal payload size is found', action='store_true')
    parser.add_argument('--predetection', help='evade the pre-detection mechanism', action='store_true')
    parser.add_argument('--l2norm', help='use L2 norm for reconstruction phase', action='store_true')
    parser.add_argument('--parallel', help='enable parallel processing', action='store_true')
    parser.add_argument('--fullreconstruct', help='perform reconstruction on full file', action='store_true')
    parser.add_argument('input_filepath', type=str, help='path to a single PE file or directory of PE files')

    args = parser.parse_args()
    attack_config = attack_config_from_program_args(args)

    if validate_output_directory(args.output_dir) == False:
        exit(1)

    if args.l2norm == True and args.parallel == False:
        warning = ("[WARN] The L2 norm reconstruction technique is slow. "
            "Run bitcamo with --parallel if you need to use this method.")
        print(colored(warning, 'white', 'on_red'))
        print('\n')

    samples = get_input_samples(args.input_filepath, args.output_dir, args.benign, args.preserve == False)
    attack(samples, attack_config)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        # Prevents massive stack trace when you press Ctrl+C
        # Does not always work when parallelism is enabled
        print('Caught exit signal. Quiting early...')
        exit(0)
