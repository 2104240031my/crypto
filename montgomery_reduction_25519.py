# def ndash(n):
#     result = 0
#     t = 0
#     r = R
#     i = 1
#     while r > 1:
#         if t % 2 == 0:
#             t = t + n
#             result = result + i
#         t = t >> 1
#         r = r >> 1
#         i = i << 1
#     return result

N  = (2 ** 252) + 0x14def9dea2f79cd65812631a5cf5d3ed
R  = 2 ** 256

# R2 := R ** 2 mod N
R2 = 0x0399411b7c309a3dceec73d217f5be65d00e1ba768859347a40611e3449c0f01

# ND where N * ND == -1 == R - 1 mod R
ND = 0x9db6c6f26fe9183614e75438ffa36beab1a206f2fdba84ffd2b51da312547e1b # ndash(N)

def MR(a):
    v = (a + (((a * ND) % R) * N)) >> 256
    if v >= N:
        return v - N
    else:
        return v

def modulo(a):
    return MR(MR(a) * R2)