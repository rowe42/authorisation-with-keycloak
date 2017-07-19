/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.example;

import com.example.model.TimedPermissions;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import org.json.JSONObject;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.stereotype.Service;

/**
 *
 * @author roland.werner
 */
@Service
public class EntitlementsService {
    
    private static final Logger LOG = Logger.getLogger(EntitlementsService.class.getName());
    
    private AuthorisationService authorisationService;
        protected OAuth2RestTemplate oauth2Template;
    
        //hack: Entitlements "Cache": user --> permissions
    private Map<String, TimedPermissions> permissions = new HashMap<>();
    
    public EntitlementsService(AuthorisationService authorisationService, OAuth2RestTemplate oauth2Template) {
        this.authorisationService = authorisationService;
        this.oauth2Template = oauth2Template;
    }
    
        /**method2 (Entitlements)
     *
     * @param permission
     * @param token
     * @return
     */
    public boolean method2(String permission, String token) {
        LOG.info("Called method2 (Entitlements) with permission " + permission);
        LOG.info("Token " + token);
        String claims = retrieveClaimsFromJWT(token);
        LocalDateTime refreshDate = calculateExpirationFromJWT(claims);
        String user = retrieveUsernameFromToken(claims);
        LOG.info("Retrieved from token: username " + user + " refreshDate " +refreshDate);
        return checkPermissionWithEntitlementsInCache(user, refreshDate, permission);
    }
    
    /**
     * Check Permission with Entitlements. Check Cache first.
     * @param user
     * @param expiration
     * @param permission
     * @return 
     */
    private boolean checkPermissionWithEntitlementsInCache(String user, LocalDateTime expiration, String permission) {
        LOG.info("Called checkPermissionWithEntitlementsInCache");
        boolean allowed = false;
        TimedPermissions timedPermissions = retrievePermissionsFromCache(user);
        LocalDateTime refreshDate = null;
        if (timedPermissions != null) {
            LOG.info("Found Permissions in cache: " + timedPermissions.getPermissions().toString());
            refreshDate = timedPermissions.getRefreshDate();
        } else {
            LOG.info("No Permissions in cache");
            timedPermissions = new TimedPermissions();
        }

        if (refreshDate != null && refreshDate.isAfter(LocalDateTime.now())) {
            //cache content still valid, not expired --> check permission in cache
            LOG.info("Permissions still valid");
            allowed = timedPermissions.hasPermission(permission);
        } else {
            //not found in cache or no longer valid --> fetch new
            LOG.info("Permissions no longer valid. RefreshDate: " + refreshDate + ", Now is " + LocalDateTime.now());
            String rpt = retrieveRPTviaEntitlements();
            Set<String> permissionsSet = authorisationService.extractPermissionsFromRPT(rpt);
            timedPermissions.setPermissions(permissionsSet);
            timedPermissions.setRefreshDate(expiration);
            addPermissionsToCache(user, timedPermissions);

            LOG.info("Permissions of user: " + timedPermissions.getPermissions().toString());
            if (permissionsSet.contains(permission)) {
                allowed = true;
            }
        }
        LOG.info("Permission checked, returning: " + allowed);
        return allowed;
    }
    
    
    private TimedPermissions retrievePermissionsFromCache(String user) {
        return permissions.get(user);
    }

    private void addPermissionsToCache(String user, TimedPermissions timedPermissions) {
        permissions.put(user, timedPermissions);
    }
    
    
    private String retrieveClaimsFromJWT(String base64Token) {
        Jwt jwt = JwtHelper.decode(base64Token);
        String claims = jwt.getClaims();
        return claims;
    }
    
    
    private LocalDateTime calculateExpirationFromJWT(String base64Token) {
        JSONObject responseJSON = new JSONObject(base64Token);
        long exp = responseJSON.getInt("exp");
        LocalDateTime ldt = LocalDateTime.ofEpochSecond(exp, 0, ZoneOffset.ofHours(2));

        //long iat = responseJSON.getInt("iat");
        //LocalDateTime ldt = LocalDateTime.now().plusSeconds(exp - iat);
        LOG.info("Calculated RefreshDate: " + ldt);

        return ldt;
    }
    
    
    private String retrieveRPTviaEntitlements() {
        LOG.info("Called retrieveEntitlements");

        String url = "http://localhost:8080/auth/realms/demo/authz/entitlement/openIdDemo";

        String response = this.oauth2Template.getForObject(url, String.class);

        JSONObject responseJSON = new JSONObject(response);

        LOG.info("entitlements retrieved");
        return responseJSON.getString("rpt");
    }
    
        
    public String retrieveUsernameFromToken(String token) {
        JSONObject responseJSON = new JSONObject(token);
        String username = responseJSON.getString("preferred_username");
        return username;
    }
}