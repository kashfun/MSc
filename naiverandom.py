import random
from collections import Counter
import matplotlib.pyplot as plt
import collections

x = []
i = 1
while i <= 512:
  x.append(int(random.getrandbits(8))%128)
  i += 1
print(x)

c = Counter(x)
oc = collections.OrderedDict(sorted(c.items()))
print(oc)

plt.bar(c.keys(), c.values(), 1, color='r')
plt.title(label='Random Numbers Generated')
