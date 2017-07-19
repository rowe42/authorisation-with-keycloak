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
    
    @Autowired    
    private final EntitlementsService entitlementsService = null;
    
    @Override
    public boolean hasPermission(Authentication a, Object o, Object o1) {
        return hasPermission(a, 1, (String) o, o1);
    }

    @Override
    public boolean hasPermission(Authentication a, Serializable srlzbl, String string, Object o) {
        LOG.info("-----------------------------------------");
        LOG.info("--------- hasPermission called. ---------");
        LOG.info("-----------------------------------------");
        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) a.getDetails();
        String tokenValue = details.getTokenValue();          
        
        String method = (String) o;
        
        boolean allowed = false;
        if (method.equals("UMA")) {
            allowed = this.authService.method1(string);
        } else if (method.equals("Entitlements")) {
            allowed = this.entitlementsService.method2(string, tokenValue);
        } else {
            LOG.info("Not supported!");
        }
        return allowed;
    }
    
}
