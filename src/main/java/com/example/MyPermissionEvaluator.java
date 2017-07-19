/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.example;

import java.io.Serializable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.stereotype.Service;

/**
 *
 * @author Roland.Werner
 */
@Service
public class MyPermissionEvaluator implements PermissionEvaluator {

    @Autowired    
    private final AuthorisationService authService = null;
    
    @Override
    public boolean hasPermission(Authentication a, Object o, Object o1) {
        System.out.println("hasPermission reached.");
        return true;
    }

    @Override
    public boolean hasPermission(Authentication a, Serializable srlzbl, String string, Object o) {
        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) a.getDetails();
        String tokenValue = details.getTokenValue();
        System.out.println("hasPermission2 reached. tokenValue: " + tokenValue + " " + string);
        
        boolean allowed = false;
        if (srlzbl.equals(1)) {
            allowed = this.authService.method1(string);
        } else {
            allowed = this.authService.method2(string);
        }
        return allowed;
    }
    
}
