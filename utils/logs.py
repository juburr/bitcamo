from termcolor import colored
from string import Formatter

def color_malicious(message):
    return colored(message, 'red')

def color_benign(message):
    return colored(message, 'green')

def color_prediction(message, y_hat):
    return colored(message, 'green' if y_hat < 0.50 else 'red')

def color_success(success):
    return colored(success, 'green' if success else 'red')

def print_error(msg):
    print(colored('[ERROR]', 'white', 'on_red') + ' ' + msg)

def print_info(msg):
    print(colored('[INFO]', 'white', 'on_magenta') + ' ' + msg)

def print_score(y_hat, description, verbose=False, prefix=''):
    score_mal = y_hat * 100
    score_ben = 100 - score_mal
    if verbose:
        print(f'{prefix}MalConv Prediction ({description}):')
        print(f'{prefix}   Malicious:', color_malicious(f'{score_mal:.4f}%'))
        print(f'{prefix}   Benign:', color_benign(f'{score_ben:.4f}%'))
    else:
        print(f'{prefix}MalConv Prediction ({description}):', color_prediction(f'{score_mal:.4f}% malicious', y_hat))

# This function was taken directly from: https://stackoverflow.com/a/42320260
# TODO: Millisecond-level precision would be nice to have
def format_timedelta(tdelta, fmt='{D:02}d {H:02}h {M:02}m {S:02}s', inputtype='timedelta'):
    if inputtype == 'timedelta':
        remainder = int(tdelta.total_seconds())
    elif inputtype in ['s', 'seconds']:
        remainder = int(tdelta)
    elif inputtype in ['m', 'minutes']:
        remainder = int(tdelta)*60
    elif inputtype in ['h', 'hours']:
        remainder = int(tdelta)*3600
    elif inputtype in ['d', 'days']:
        remainder = int(tdelta)*86400
    elif inputtype in ['w', 'weeks']:
        remainder = int(tdelta)*604800

    f = Formatter()
    desired_fields = [field_tuple[1] for field_tuple in f.parse(fmt)]
    possible_fields = ('W', 'D', 'H', 'M', 'S')
    constants = {'W': 604800, 'D': 86400, 'H': 3600, 'M': 60, 'S': 1}
    values = {}
    for field in possible_fields:
        if field in desired_fields and field in constants:
            values[field], remainder = divmod(remainder, constants[field])
    return f.format(fmt, **values)