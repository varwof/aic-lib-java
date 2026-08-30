package com.varwof.aic;

/**
 * Signals an encoding/decoding/validation problem in an AIC structure.
 * Mirrors the semantics of the Go reference implementation's error returns.
 */
public class AicException extends RuntimeException {
    public AicException(String message) {
        super(message);
    }

    public AicException(String message, Throwable cause) {
        super(message, cause);
    }
}