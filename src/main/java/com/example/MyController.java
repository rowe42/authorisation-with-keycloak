package com.example;

import de.muenchen.referenzarchitektur.authorisationLib.EntitlementsService;
import java.util.Set;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.logging.Logger;
import javax.validation.Valid;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

/**
 *
 * @author straubec
 */
@RestController
public class MyController {

    private final MyServiceClient service;
    private final EntitlementsService entitlementsService;

    private static final Logger LOG = Logger.getLogger(MyController.class.getName());

    public MyController(MyServiceClient service, EntitlementsService entitlementsService) {
        this.service = service;
        this.entitlementsService = entitlementsService;
    }

//    @PreAuthorize("hasAuthority('RESOURCE_001_HELLO')")
    @RequestMapping(value = "/hello", method = RequestMethod.POST)
    public String sayHello(@Valid @RequestBody Hello hello) {
        return this.service.sayHello(hello);
    }

    @RequestMapping(value = "/getPermissions", method = RequestMethod.GET)
    public String getPermissions() {
        Set<String> permissions = entitlementsService.getPermissions(false);
        if (permissions != null) {
            return permissions.toString();
        } else {
            return "No Permissions found.";
        }
    }

    @PreAuthorize("hasPermission(#permission, 'UMA')")
    @RequestMapping(value = "/methodUMA", method = RequestMethod.GET)
    public String callMethodUMA(@Valid @RequestParam String permission) {
        return "executed callMethodUMA";
    }

    //@PreAuthorize("hasPermission('resource1', 'UMA')")
    @PreAuthorize("hasPermission(T(com.example.ResourcesEnum).RESOURCE1.name(), 'UMA')")
    @RequestMapping(value = "/methodUMA1", method = RequestMethod.GET)
    public String callMethodUMA1() {
        return "executed callMethodUMA1";
    }

    @PreAuthorize("hasPermission(T(com.example.ResourcesEnum).RESOURCE2.name(), 'UMA')")
    @RequestMapping(value = "/methodUMA2", method = RequestMethod.GET)
    public String callMethodUMA2() {
        return "executed callMethodUMA2";
    }

    @PreAuthorize("hasPermission(T(com.example.ResourcesEnum).RESOURCE3.name(), 'UMA')")
    @RequestMapping(value = "/methodUMA3", method = RequestMethod.GET)
    public String callMethodUMA3() {
        return "executed callMethodUMA3";
    }

    @PreAuthorize("hasPermission(#permission, 'Entitlements')")
    @RequestMapping(value = "/methodEntitlements", method = RequestMethod.GET)
    public String callmethodEntitlements(@Valid @RequestParam String permission) {
        return "executed callmethodEntitlements";
    }

    @PreAuthorize("hasPermission(T(com.example.ResourcesEnum).RESOURCE1.name(), 'Entitlements')")
    @RequestMapping(value = "/methodEntitlements1", method = RequestMethod.GET)
    public String callmethodEntitlements1() {
        return "executed callmethodEntitlements1";
    }

    @PreAuthorize("hasPermission(T(com.example.ResourcesEnum).RESOURCE2.name(), 'Entitlements')")
    @RequestMapping(value = "/methodEntitlements2", method = RequestMethod.GET)
    public String callmethodEntitlements2() {
        return "executed callmethodEntitlements2";
    }

    @PreAuthorize("hasPermission(T(com.example.ResourcesEnum).RESOURCE3.name(), 'Entitlements')")
    @RequestMapping(value = "/methodEntitlements3", method = RequestMethod.GET)
    public String callmethodEntitlements3() {
        return "executed callmethodEntitlements3";
    }

    @PreAuthorize("hasPermission(#permission, 'EntitlementsKeyCloakAPI')")
    @RequestMapping(value = "/methodEntitlementsKeyCloak", method = RequestMethod.GET)
    public String callmethodEntitlementsKeyCloakAPI(@Valid @RequestParam String permission) {
        return "executed callmethodEntitlements";
    }

    @PreAuthorize("hasPermission(T(com.example.ResourcesEnum).RESOURCE1.name(), 'EntitlementsKeyCloakAPI')")
    @RequestMapping(value = "/methodEntitlements1KeyCloak", method = RequestMethod.GET)
    public String callmethodEntitlements1KeyCloakAPI() {
        return "executed callmethodEntitlements1";
    }

    @PreAuthorize("hasPermission(T(com.example.ResourcesEnum).RESOURCE2.name(), 'EntitlementsKeyCloakAPI')")
    @RequestMapping(value = "/methodEntitlements2KeyCloak", method = RequestMethod.GET)
    public String callmethodEntitlements2KeyCloakAPI() {
        return "executed callmethodEntitlements2";
    }

    @PreAuthorize("hasPermission(T(com.example.ResourcesEnum).RESOURCE3.name(), 'EntitlementsKeyCloakAPI')")
    @RequestMapping(value = "/methodEntitlements3KeyCloak", method = RequestMethod.GET)
    public String callmethodEntitlements3KeyCloakAPI() {
        return "executed callmethodEntitlements3";
    }

    @PreAuthorize("hasPermission(#permission, 'EntitlementsNoCache')")
    @RequestMapping(value = "/methodEntitlementsNoCache", method = RequestMethod.GET)
    public String callmethodEntitlementsNoCache(@Valid @RequestParam String permission) {
        return "executed callmethodEntitlements";
    }

    @PreAuthorize("hasPermission(T(com.example.ResourcesEnum).RESOURCE1.name(), 'EntitlementsNoCache')")
    @RequestMapping(value = "/methodEntitlements1NoCache", method = RequestMethod.GET)
    public String callmethodEntitlements1NoCache() {
        return "executed callmethodEntitlements1";
    }

    @PreAuthorize("hasPermission(T(com.example.ResourcesEnum).RESOURCE2.name(), 'EntitlementsNoCache')")
    @RequestMapping(value = "/methodEntitlements2NoCache", method = RequestMethod.GET)
    public String callmethodEntitlements2NoCache() {
        return "executed callmethodEntitlements2";
    }

    @PreAuthorize("hasPermission(T(com.example.ResourcesEnum).RESOURCE3.name(), 'EntitlementsNoCache')")
    @RequestMapping(value = "/methodEntitlements3NoCache", method = RequestMethod.GET)
    public String callmethodEntitlements3NoCache() {
        return "executed callmethodEntitlements3";
    }
}
