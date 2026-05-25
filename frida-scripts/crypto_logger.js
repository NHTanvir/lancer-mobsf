Java.perform(function() {
    'use strict';

    var results = [];

    // Cipher.doFinal - log plaintext and key
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.doFinal.overload('[B').implementation = function(input) {
            var result = this.doFinal(input);
            var algorithm = this.getAlgorithm();
            console.log('[lancer-crypto] Cipher.doFinal algorithm=' + algorithm +
                       ' input_len=' + input.length +
                       ' output_len=' + result.length);
            // Convert to hex for logging
            var hex = Array.from(input).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
            console.log('[lancer-crypto] input_hex=' + hex.substring(0, 64) + (hex.length > 64 ? '...' : ''));
            return result;
        };
    } catch(e) {}

    // MessageDigest - log hash inputs
    try {
        var MessageDigest = Java.use('java.security.MessageDigest');
        MessageDigest.digest.overload('[B').implementation = function(input) {
            var result = this.digest(input);
            var algorithm = this.getAlgorithm();
            var inputStr = Java.use('java.lang.String').$new(input, 'UTF-8');
            console.log('[lancer-crypto] MessageDigest.digest algorithm=' + algorithm + ' input=' + inputStr.substring(0, 100));
            return result;
        };
    } catch(e) {}

    console.log('[lancer-crypto] Crypto logger installed');
});
