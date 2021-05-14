from bleichenbacher.oracle import padding_oracle_test

tests = [
    b'', bytes([0,2,1,2,3,4,1,2,3,5,0,1,2,3,4]), bytes([9,9,9,2,3,0,4,5]), 
    bytes([0,0,0,2,1,1,2,3,2,1,2,3,3,0,4]), bytes([0,2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,2,3]),
     bytes()
]
outputs = [
    False, True, False, False, True, False
]

for i in range(len(tests)):
    if padding_oracle_test(tests[i])!=outputs[i]:
        print(tests[i])
        