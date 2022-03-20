import numpy as np
import random
from utils.os import exit

malicious_distribution = {33: 20517, 133: 19526, 116: 17636, 104: 15134, 89: 14619, 139: 14616, 106: 13429, 2: 12444, 32: 12386, 69: 11786, 99: 10958, 105: 10519, 232: 9925, 120: 8839, 101: 8702, 100: 8605, 43: 8260, 40: 8222, 5: 8189, 251: 8134, 198: 7434, 64: 7392, 224: 7125, 82: 6799, 111: 6779, 97: 6567, 160: 6451, 86: 6446, 129: 6384, 210: 6235, 84: 6194, 3: 5611, 44: 5387, 52: 5319, 117: 5069, 1: 4849, 6: 4791, 46: 4679, 65: 4416, 87: 4362, 102: 4177, 252: 4133, 199: 4062, 128: 4024, 242: 3997, 88: 3983, 108: 3880, 67: 3808, 16: 3641, 50: 3604, 124: 3574, 233: 3302, 107: 3256, 80: 3246, 17: 3200, 255: 3194, 122: 3068, 48: 3049, 95: 3046, 10: 2885, 194: 2819, 22: 2816, 19: 2809, 207: 2769, 248: 2742, 201: 2563, 77: 2562, 0: 2394, 4: 2346, 236: 2323, 45: 2311, 145: 2264, 153: 2262, 93: 2090, 169: 2034, 192: 1916, 28: 1914, 213: 1894, 7: 1854, 114: 1826, 141: 1533, 239: 1528, 144: 1378, 58: 1357, 110: 1324, 119: 1305, 170: 1282, 171: 1186, 25: 1185, 131: 1145, 152: 1100, 55: 1091, 200: 1069, 71: 1013, 202: 959, 85: 947, 98: 897, 191: 878, 113: 869, 49: 866, 76: 861, 12: 792, 197: 789, 138: 780, 94: 723, 63: 699, 75: 682, 61: 635, 83: 610, 234: 599, 121: 512, 36: 450, 181: 416, 81: 416, 142: 409, 208: 403, 70: 386, 177: 385, 24: 329, 230: 318, 60: 307, 126: 300, 214: 295, 112: 295, 73: 242, 178: 224, 209: 219, 237: 218, 149: 213, 15: 199, 51: 190, 96: 168, 216: 164, 185: 155, 57: 148, 90: 146, 175: 141, 162: 138, 130: 134, 148: 129, 176: 124, 78: 118, 92: 113, 155: 102, 159: 97, 136: 87, 115: 83, 184: 81, 186: 72, 250: 67, 196: 63, 204: 46, 215: 44, 226: 38, 79: 30, 229: 30, 212: 28, 41: 22, 125: 18, 157: 17, 163: 15, 206: 13, 228: 11, 118: 10, 168: 9, 47: 9, 74: 8, 173: 7, 254: 6, 247: 5, 249: 5, 225: 4, 158: 4, 103: 4, 29: 4, 227: 4, 166: 3, 21: 3, 211: 3, 8: 3, 235: 3, 42: 2, 140: 2, 14: 2, 109: 2, 167: 2, 156: 2, 30: 2, 154: 1, 218: 1, 91: 1, 31: 1, 241: 1, 54: 1}
benign_distribution = {0: 107623, 139: 37430, 63: 27122, 104: 19107, 106: 17897, 116: 16626, 32: 15095, 111: 14958, 33: 12051, 69: 11205, 45: 11047, 232: 10910, 97: 10866, 199: 10402, 133: 9383, 102: 8053, 99: 7461, 3: 7244, 86: 7185, 101: 7115, 128: 6936, 2: 6910, 105: 6340, 129: 6167, 5: 5200, 100: 5146, 4: 4829, 89: 4768, 255: 4510, 64: 4436, 224: 4422, 52: 4220, 17: 4132, 40: 3923, 233: 3881, 242: 3881, 44: 3857, 19: 3805, 65: 3739, 95: 3545, 43: 3428, 251: 3348, 120: 3330, 160: 2996, 141: 2812, 84: 2810, 80: 2766, 198: 2618, 16: 2592, 82: 2572, 1: 2462, 6: 2382, 192: 2350, 169: 2316, 48: 2243, 50: 2193, 46: 2159, 210: 2119, 77: 1799, 170: 1793, 252: 1754, 88: 1657, 107: 1635, 191: 1592, 28: 1470, 108: 1385, 122: 1328, 117: 1315, 197: 1279, 87: 1242, 71: 1240, 12: 1157, 83: 1147, 126: 1022, 201: 978, 10: 927, 144: 880, 236: 877, 153: 797, 213: 797, 49: 776, 7: 775, 58: 764, 110: 746, 93: 658, 24: 646, 79: 621, 92: 521, 81: 514, 200: 512, 248: 471, 25: 465, 124: 429, 207: 319, 36: 275, 61: 148, 67: 73, 98: 48, 152: 32, 239: 30, 75: 29, 76: 25, 22: 20, 119: 18, 73: 18, 94: 13, 145: 13, 148: 10, 149: 8, 121: 6, 57: 6, 131: 5, 171: 4, 114: 2, 155: 2, 177: 1, 70: 1, 194: 1, 234: 1}

def print_usage_instructions(algo):
    print(f'Invalid byte initialization strategy: \'{algo}\'.')
    print(f'Valid options are: random, psuedorandom, ones, zeros, weighted, or a value between 0-255')

def initialize(algo, size, input_benign):
    if algo == '':
        # Optimal byte initializations from Burr (2022).
        # TODO: Must determine optimal byte for benign inputs. 205 works well enough for now.
        algo = '191' if input_benign == False else '205'

    if algo == 'random':
        return random_initialize(size)
    if algo == 'pseudorandom':
        return pseudorandom_initialize(size)
    if algo == 'ones':
        return ones_initialize(size)
    if algo == 'zeros':
        return zeros_initialize(size)
    if algo == 'weighted':
        return weighted_initialize(size, input_benign)

    # Expecting algo to be an integer between 0-255 at this point
    try:
        byte_val = int(algo)
    except:
        print_usage_instructions(algo)
        exit(1)
    if byte_val < 0 or byte_val > 255:
        print_usage_instructions(algo)
        exit(1)
    return value_initialize(size, byte_val)

def random_initialize(size):
    return np.random.randint(0, 256, size, dtype=np.uint8).tobytes()

def pseudorandom_initialize(size, seed=1337):
    rng = np.random.default_rng(seed)
    return rng.integers(low=0, high=256, size=size).tobytes()

def ones_initialize(size):
    return np.ones(size, dtype=np.uint8).tobytes()

def zeros_initialize(size):
    return np.zeros(size, dtype=np.uint8).tobytes()

def value_initialize(size, val):
    payload = np.zeros(size, dtype=np.uint8)
    for i in range(len(payload)):
        payload[i] = val
    return bytes(payload)

def weighted_initialize(size, input_benign):
    if input_benign:
        bytesList = list(malicious_distribution.keys())
        weightsList = list(malicious_distribution.values())
    else:
        bytesList = list(benign_distribution.keys())
        weightsList = list(benign_distribution.values())
    pattern = random.choices(bytesList, weights=weightsList, k=size)
    return bytes(pattern)