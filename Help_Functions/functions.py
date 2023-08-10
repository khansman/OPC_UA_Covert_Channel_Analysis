import math
import random
from scipy.interpolate import interp1d


def linear(old_value):
    m = interp1d([0, 512], [-1, 1])
    if old_value < 512:
        return_v = m(old_value+1)
        return round(float(return_v), 3), old_value + 1
    else:
        return_v = m(old_value)
        return round(float(return_v), 3), old_value


def random_value(low, high):
    m = interp1d([low, high], [-0.75, 0.75])
    random_v = random.randrange(low, high)
    return round(float(m(random_v)), 3), random_v


def sinus(old_value):
    return round(math.sin(old_value), 3), old_value+(1/6*math.pi)


def cosinus(old_value):
    return round(math.cos(old_value), 3), old_value+(1/6*math.pi)
