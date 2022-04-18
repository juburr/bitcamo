from utils.logs import format_timedelta

from statistics import mean, median, stdev
from collections import Counter
from pandas import DataFrame
from numpy import percentile

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

def print_duration_stats(durations):
    pd_durations = DataFrame(durations)
    duration_tot = pd_durations.sum().dt.to_pytimedelta().item()
    duration_avg = pd_durations.mean().dt.to_pytimedelta().item()
    duration_med = pd_durations.median().dt.to_pytimedelta().item()
    duration_std = pd_durations.std().dt.to_pytimedelta().item()
    duration_min = pd_durations.min().dt.to_pytimedelta().item()
    duration_max = pd_durations.max().dt.to_pytimedelta().item()
    duration_1qt = pd_durations.quantile(0.25, numeric_only=False).dt.to_pytimedelta().item()
    duration_3qt = pd_durations.quantile(0.75, numeric_only=False).dt.to_pytimedelta().item()

    print(f'      Tot: {format_timedelta(duration_tot)}')
    print(f'      Avg: {format_timedelta(duration_avg)}')
    print(f'      Std: {format_timedelta(duration_std)}')
    print(f'      Min: {format_timedelta(duration_min)}')
    print(f'      1Qt: {format_timedelta(duration_1qt)}')
    print(f'      Med: {format_timedelta(duration_med)}')
    print(f'      3Qt: {format_timedelta(duration_3qt)}')
    print(f'      Max: {format_timedelta(duration_max)}')

def print_stats_summary(numlist, prefix='      ', integers_only=False, include_sum=True):
    formatter = '' if integers_only else '.4f'

    numlist_cnt = len(numlist)
    numlist_sum = sum(numlist)
    numlist_avg = mean(numlist)
    numlist_med = median(numlist)
    numlist_std = stdev(numlist) if len(numlist) > 1 else 0.0
    numlist_min = min(numlist)
    numlist_max = max(numlist)
    numlist_1qt = percentile(numlist, 25)
    numlist_3qt = percentile(numlist, 75)

    print(f'{prefix}Cnt: {numlist_cnt}')
    if include_sum:
        print(f'{prefix}Tot: {numlist_sum:{formatter}}')
    print(f'{prefix}Avg: {numlist_avg:.4f}')
    print(f'{prefix}Std: {numlist_std:.4f}')
    print(f'{prefix}Min: {numlist_min:{formatter}}')
    print(f'{prefix}1Qt: {numlist_1qt:.4f}')
    print(f'{prefix}Med: {numlist_med:.4f}')
    print(f'{prefix}3Qt: {numlist_3qt:.4f}')
    print(f'{prefix}Max: {numlist_max:{formatter}}')