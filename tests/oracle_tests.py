from ..bleichenbacher import oracle

tests = [
    b'', b'021234123501234', b'023045', b'000211232123304', 
    b'0211111111111111111023'
]
outputs = [
    False, True, False, False, True
]

for i in range(len(test)):
    if padding_oracle(tests[i])!=outputs[i]:
        print(tests[i])
        