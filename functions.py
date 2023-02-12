import math
import random
from scipy.interpolate import interp1d


def linear(old_value):
    m = interp1d([0, 512], [-1, 1])
    if old_value < 512:
        return_v = m(old_value+1)
        return float(return_v), old_value + 1
    else:
        return_v = m(old_value)
        return float(return_v), old_value


def random_value(low, high):
    m = interp1d([low, high], [-1, 1])
    random_v = random.randrange(low, high)
    return float(m(random_v)), random_v


def sinus(old_value):
    return math.sin(old_value), old_value+(1/6*math.pi)


def cosinus(old_value):
    return math.cos(old_value), old_value+(1/6*math.pi)
