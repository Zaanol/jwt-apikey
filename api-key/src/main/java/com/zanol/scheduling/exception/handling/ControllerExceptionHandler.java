package com.zanol.scheduling.exception.handling;

import com.zanol.scheduling.exception.model.ErrorMessage;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

@ControllerAdvice
public class ControllerExceptionHandler {

    @ExceptionHandler(BadCredentialsException.class)
    private ResponseEntity<ErrorMessage> handleExpirationToken(Exception ex) {
        return new ResponseEntity<>(new ErrorMessage(ex.getMessage()), HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    private ResponseEntity<ErrorMessage> handleIntegrityViolation(DataIntegrityViolationException ex, WebRequest request) {
        if (ex.getCause() instanceof ConstraintViolationException) {
            return handleConstraintViolation((ConstraintViolationException) ex.getCause());
        }

        return handleGenericError(ex, request);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    private ResponseEntity<ErrorMessage> handleConstraintViolation(ConstraintViolationException ex) {
        return new ResponseEntity<>(
            new ErrorMessage(ex.getCause().getMessage()),
            HttpStatus.INTERNAL_SERVER_ERROR
        );
    }

    @ExceptionHandler(Exception.class)
    private ResponseEntity<ErrorMessage> handleGenericError(Exception ex, WebRequest request) {
        return new ResponseEntity<>(new ErrorMessage(ex.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }
}