from collections import Counter

def byte_distribution(x):
    distribution = Counter(bytearray(x))
    return distribution

def combine_byte_distributions(samples, successful_only=True):
    combined = Counter()
    for s in samples:
        if s.results.best_result.payload_byte_distribution is None:
            continue
        if successful_only and s.results.best_result.evades_malconv == False:
            continue
        combined = combined + s.results.best_result.payload_byte_distribution
    return combined

def print_distribution_tuples(ctr, prefix=''):
    for i in ctr:
        print(f'{prefix}[byte {i[0]}]: {i[1]}')