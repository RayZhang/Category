//
//  NSData+CommonCrypto.h
//
//  Created by Ray Zhang on 13-3-1.
//  Copyright (c) 2013年 Ray Zhang. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (CommonCrypto)

- (NSString *)MD5;
- (NSString *)SHAWithDigestLength:(NSUInteger)length;

- (NSData *)DESEncryptWithKey:(NSString *)encryptKey;
- (NSData *)DESDecryptWithKey:(NSString *)decryptKey;

- (NSData *)AES256EncryptWithKey:(NSString *)encryptKey;
- (NSData *)AES256DecryptWithKey:(NSString *)decryptKey;

@end
