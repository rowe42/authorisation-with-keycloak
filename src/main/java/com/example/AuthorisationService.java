package com.example;

import com.example.model.TimedPermissions;
import com.example.model.TimedPermissionTicket;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.cloud.client.circuitbreaker.EnableCircuitBreaker;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

/**
 *
 * @author straubec
 */
@Service
@EnableCircuitBreaker
public class AuthorisationService {

    private static final Logger LOG = Logger.getLogger(AuthorisationService.class.getName());

    protected RestTemplate template;
    protected OAuth2RestTemplate oauth2Template;

    //hack: Permission Ticket "cache": permission --> TimedPermission
    private Map<String, TimedPermissionTicket> permissionTickets = new HashMap<>();

    //hack: Entitlements "Cache": user --> permissions
    private Map<String, TimedPermissions> permissions = new HashMap<>();

    public AuthorisationService(RestTemplate template, OAuth2RestTemplate oauth2Template) {
        this.template = template;
        this.oauth2Template = oauth2Template;
    }

    public boolean method1(String permission) {
        LOG.info("Called method1 (UMA) with permission " + permission);
        return checkPermissionWithUMA(permission);
    }

    public boolean method2(String permission, String token) {
        LOG.info("Called method2 (Entitlements) with permission " + permission);
        LOG.info("Token " + token);
        String claims = retrieveClaimsFromJWT(token);
        LocalDateTime refreshDate = calculateExpirationFromJWT(claims);
        String user = retrieveUsernameFromToken(claims);
        LOG.info("Retrieved from token: username " + user + " refreshDate " +refreshDate);
        return checkPermissionWithEntitlementsInCache(user, refreshDate, permission);
    }

    private boolean checkPermissionWithUMA(String permission) {
        LOG.info("Called checkPermissionWithUMA");
        boolean allowed = false;

        //check whether we have permission ticket in "cache", otherwise fetch new
        String permissionTicket = accessPermissionTicket(permission);

        if (permissionTicket != null) {
            try {
                //with permissionTicket, retrieve Authorisation for the given permission
                String rpt = retrieveRPTviaUMA(permissionTicket);
                allowed = checkPermissionFromRPT(rpt, permission);
            } catch (HttpClientErrorException e) {
                LOG.info("Caught HttpClientErrorException - User not permitted");
            }
        }

        return allowed;
    }

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
            Set<String> permissionsSet = extractPermissionsFromRPT(rpt);
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

    private boolean checkPermissionWithEntitlements(String permission) {
        String rpt = retrieveRPTviaEntitlements();
        return checkPermissionFromRPT(rpt, permission);
    }

    private boolean checkPermissionFromRPT(String rpt, String permission) {
        boolean allowed = false;
        Set<String> permissionsSet = extractPermissionsFromRPT(rpt);
        if (permissionsSet.contains(permission)) {
            allowed = true;
        }
        return allowed;
    }

    private TimedPermissions retrievePermissionsFromCache(String user) {
        return permissions.get(user);
    }

    private void addPermissionsToCache(String user, TimedPermissions timedPermissions) {
        permissions.put(user, timedPermissions);
    }

    private String accessPermissionTicket(String permission) {
        LocalDateTime refreshDate = null;
        String permissionTicket = null;

        //try to fetch permission from "cache"
        TimedPermissionTicket timedPermission = permissionTickets.get(permission);
        if (timedPermission != null) {
            LOG.info("Found Permission Ticket in Cache");
            refreshDate = timedPermission.getRefreshDate();
            permissionTicket = timedPermission.getPermissionTicket();
        }

        //first of all check whether access token is not existing or not valid
        if (refreshDate == null || refreshDate.isBefore(LocalDateTime.now())) {
            LOG.info("RefreshDate is not valid: " + refreshDate);
            //fetch new access token jwt
            String clientAccessToken = retrieveClientAccessToken();

            //retrieve access_token und expires_in
            JSONObject responseJSON = new JSONObject(clientAccessToken);
            String accessToken = responseJSON.getString("access_token");

            //fetch new permission ticket
            try {
                permissionTicket = retrievePermissionTicket(accessToken, permission);
                LOG.info("Fetched new permission ticket");
            } catch (HttpClientErrorException e) {
                LOG.info("Caught HttpClientErrorException - Permission not found");
            }

            //put new refreshDate "expiresIn" seconds in the future            
            refreshDate = retrieveRefreshDateFromToken(clientAccessToken);
            timedPermission = new TimedPermissionTicket();
            timedPermission.setRefreshDate(refreshDate);
            timedPermission.setPermissionTicket(permissionTicket);
            permissionTickets.put(permission, timedPermission);
            LOG.info("Put permission in cache: " + permission);

        }

        return permissionTicket;
    }

    private String retrieveClaimsFromJWT(String base64Token) {
        Jwt jwt = JwtHelper.decode(base64Token);
        String claims = jwt.getClaims();
        return claims;
    }
    
    private LocalDateTime retrieveRefreshDateFromToken(String token) {
        int expiresIn = retrieveExpirationFromToken(token);
        LocalDateTime refreshDate = LocalDateTime.now().plusSeconds(expiresIn);
        return refreshDate;
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

    private int retrieveExpirationFromToken(String token) {
        JSONObject responseJSON = new JSONObject(token);
        int expiresIn = responseJSON.getInt("expires_in");
        return expiresIn;
    }
    
    private String retrieveUsernameFromToken(String token) {
        JSONObject responseJSON = new JSONObject(token);
        String username = responseJSON.getString("preferred_username");
        return username;
    }
    

    private String retrieveClientAccessToken() {
        LOG.info("Called retrieveAccessToken");
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "client_credentials");
        map.add("client_id", "openIdDemo");
        map.add("scope", "uma_authorization");
        map.add("client_secret", "29a1ded3-eadf-46cf-9af3-18cad9721691");

        String url = "http://localhost:8080/auth/realms/demo/protocol/openid-connect/token";

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        ResponseEntity<String> response = this.template.postForEntity(url, request, String.class);

        LOG.info("access token retrieved");
        return response.getBody();
    }

    private String retrievePermissionTicket(String accessToken, String resource) {
        LOG.info("Called retrievePermissionTicket");
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + accessToken);

        JSONObject body = new JSONObject().put("resource_set_name", resource);

        String url = "http://localhost:8080/auth/realms/demo/authz/protection/permission";

        HttpEntity<String> request = new HttpEntity<>(body.toString(), headers);

        ResponseEntity<String> response = this.template.postForEntity(url, request, String.class);
        JSONObject responseJSON = new JSONObject(response.getBody());

        LOG.info("permission ticket retrieved");
        return responseJSON.getString("ticket");
    }

    private String retrieveRPTviaEntitlements() {
        LOG.info("Called retrieveEntitlements");

        String url = "http://localhost:8080/auth/realms/demo/authz/entitlement/openIdDemo";

        String response = this.oauth2Template.getForObject(url, String.class);

        JSONObject responseJSON = new JSONObject(response);

        LOG.info("entitlements retrieved");
        return responseJSON.getString("rpt");
    }

    private String retrieveRPTviaUMA(String permissionTicket) {
        LOG.info("Called retrieveAuthorisation");
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        JSONObject body = new JSONObject().put("ticket", permissionTicket);

        String url = "http://localhost:8080/auth/realms/demo/authz/authorize";

        HttpEntity<String> request = new HttpEntity<>(body.toString(), headers);

        ResponseEntity<String> response = this.oauth2Template.postForEntity(url, request, String.class);
        JSONObject responseJSON = new JSONObject(response.getBody());

        LOG.info("authorisation retrieved");
        return responseJSON.getString("rpt");
    }

    private Set<String> extractPermissionsFromRPT(String authorisationToken) {
        Set<String> resourceSetList = new HashSet<>();
        Jwt jwt = JwtHelper.decode(authorisationToken);
        if (jwt != null) {
            String claims = jwt.getClaims();
            if (claims != null) {
                JSONObject json = new JSONObject(claims);
                if (json != null) {
                    JSONObject authorization = json.getJSONObject("authorization");
                    if (authorization != null) {
                        JSONArray array = authorization.getJSONArray("permissions");
                        if (array != null && array.length() > 0) {
                            for (int i = 0; i < array.length(); i++) {
                                JSONObject resource = (JSONObject) array.get(i);
                                if (resource != null && resource.get("resource_set_name") != null) {
                                    String resourceSetName = resource.get("resource_set_name").toString();
                                    resourceSetList.add(resourceSetName);
                                } else {
                                    throw new RuntimeException("Resource not found");
                                }
                            }
                        } else {
                            throw new RuntimeException("permissions not filled");
                        }
                    } else {
                        throw new RuntimeException("Array not filled");
                    }
                } else {
                    throw new RuntimeException("authorization not filled");
                }
            } else {
                throw new RuntimeException("claims not filled");
            }
        } else {
            throw new RuntimeException("no claims");
        }
        return resourceSetList;
    }

}
