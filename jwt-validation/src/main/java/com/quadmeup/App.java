package com.quadmeup;

import java.security.InvalidParameterException;

import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {

        final JwtValidator validator = new JwtValidator();

        try {
            DecodedJWT token = validator.validate("lorem.Ipsum.dolor");
            System.out.println( "Jwt is valid" );
        } catch (InvalidParameterException e) {
            System.out.println( "Jwt is invalid" );
            e.printStackTrace();
        }

    }
}
