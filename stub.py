
from heaplib import HeapPayloadCrafter, HeaplibException
hpc = HeapPayloadCrafter(0x41414141, 0x42424242, post_length=20, pre_length=100, pre_preset={99:"Z"})
print hpc.generate_payload()


#hpc = HeapPayloadCrafter(0x41414141, 0x42424242, post_length=20, pre={0: "Z"*4}, pre_length=100)
#print hpc.generate_payload()

#hpc = HeapPayloadCrafter(0x41414141, 0x42424242, post_length=20, pre={0: "Z"*5}, pre_length=100)
#print hpc.generate_payload()
