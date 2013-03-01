//
//  NSData+CommonCrypto.m
//
//  Created by Ray Zhang on 13-3-1.
//  Copyright (c) 2013年 Ray Zhang. All rights reserved.
//

#import "NSData+CommonCrypto.h"

#include <CommonCrypto/CommonCrypto.h>

typedef uint32_t CCKeySize;

@implementation NSData (CommonCrypto)

- (NSString *)MD5 {
    unsigned char md5Buffer[CC_MD5_DIGEST_LENGTH] = {0};
    
    CC_MD5(self.bytes, self.length, md5Buffer);
    
    NSMutableString *retVal = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [retVal appendFormat:@"%02x",md5Buffer[i]];
    }
    
    return retVal;
}

- (NSString *)SHAWithDigestLength:(NSUInteger)length {
    unsigned char *shaBuffer = (unsigned char *)malloc(length);
    memset(shaBuffer, 0, length);
    
    switch (length) {
        case CC_SHA1_DIGEST_LENGTH:
            CC_SHA1(self.bytes, self.length, shaBuffer);
            break;
        case CC_SHA224_DIGEST_LENGTH:
            CC_SHA224(self.bytes, self.length, shaBuffer);
            break;
        case CC_SHA256_DIGEST_LENGTH:
            CC_SHA256(self.bytes, self.length, shaBuffer);
            break;
        case CC_SHA384_DIGEST_LENGTH:
            CC_SHA384(self.bytes, self.length, shaBuffer);
            break;
        case CC_SHA512_DIGEST_LENGTH:
            CC_SHA512(self.bytes, self.length, shaBuffer);
            break;
        default:
            free(shaBuffer);
            return @"";
    }
    
    NSMutableString *retVal = [NSMutableString stringWithCapacity:(length * 2)];
    
    for (int i = 0; i < length; i++) {
        [retVal appendFormat:@"%02x", shaBuffer[i]];
    }
    
    free(shaBuffer);

    return retVal;
}

- (id)cryptWithOperation:(CCOperation)operation
               algorithm:(CCAlgorithm)algorithm
                 options:(CCOptions)options
                     key:(NSString *)cryptKey
                    size:(CCKeySize)size {
    NSData *retVal = nil;
    
    char *key = (char *)malloc(size + 1);
    memset(key, 0, size + 1);
    
    [cryptKey getCString:key maxLength:(size + 1) encoding:NSUTF8StringEncoding];
    
    size_t dataInLength = [self length];
    
    // For block ciphers, the output size will always be less than or equal to the input size plus the size of one block
    size_t dataOutAvailable = dataInLength + size;
    void *dataOut = malloc(dataOutAvailable);
    
    size_t dataOutMoved = 0;
    
    CCCryptorStatus status = CCCrypt(operation, algorithm, options,
                                     key, size,
                                     NULL, /* initialization vector */
                                     [self bytes], dataInLength,
                                     dataOut, dataOutAvailable,
                                     &dataOutMoved);
    
    if (status == kCCSuccess) {
        retVal = [NSData dataWithBytes:dataOut length:dataOutMoved];
    }
    
    free(dataOut);
    free(key);
    
    return retVal;
}

- (id)DESEncryptWithKey:(NSString *)encryptKey {
    return [self cryptWithOperation:kCCEncrypt algorithm:kCCAlgorithmDES options:kCCOptionPKCS7Padding | kCCOptionECBMode key:encryptKey size:kCCKeySizeDES];
}

- (id)DESDecryptWithKey:(NSString *)decryptKey {
    return [self cryptWithOperation:kCCDecrypt algorithm:kCCAlgorithmDES options:kCCOptionPKCS7Padding | kCCOptionECBMode key:decryptKey size:kCCKeySizeDES];
}

- (id)AES256EncryptWithKey:(NSString *)encryptKey {
    return [self cryptWithOperation:kCCEncrypt algorithm:kCCAlgorithmAES128 options:kCCOptionPKCS7Padding | kCCOptionECBMode key:encryptKey size:kCCKeySizeAES256];
}

- (id)AES256DecryptWithKey:(NSString *)decryptKey {
    return [self cryptWithOperation:kCCDecrypt algorithm:kCCAlgorithmAES128 options:kCCOptionPKCS7Padding | kCCOptionECBMode key:decryptKey size:kCCKeySizeAES256];
}

@end
