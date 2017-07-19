/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.example;

import java.io.Serializable;
import java.util.logging.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.stereotype.Service;

/**
 *
 * @author Roland.Werner
 */
@Service
public class MyPermissionEvaluator implements PermissionEvaluator {

    private static final Logger LOG = Logger.getLogger(MyPermissionEvaluator.class.getName());
    @Autowired    
    private final AuthorisationService authService = null;
    
    @Override
    public boolean hasPermission(Authentication a, Object o, Object o1) {
        LOG.info("hasPermission called.");
        return true;
    }

    @Override
    public boolean hasPermission(Authentication a, Serializable srlzbl, String string, Object o) {
        LOG.info("hasPermission called.");
        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) a.getDetails();
        String tokenValue = details.getTokenValue();
        LOG.info("Principal " + ((OAuth2Authentication) a).getPrincipal());
        LOG.info("Credential " + ((OAuth2Authentication) a).getCredentials());
        LOG.info("Name " + ((OAuth2Authentication) a).getUserAuthentication().getName());        
        
        
        
        boolean allowed = false;
        if (srlzbl.equals(1)) {
            allowed = this.authService.method1(string);
        } else {
            allowed = this.authService.method2(string, tokenValue);
        }
        return allowed;
    }
    
}
