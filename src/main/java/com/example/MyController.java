package com.example;

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
    private final AuthorisationService authService;

    private static final Logger LOG = Logger.getLogger(MyController.class.getName());

    public MyController(MyServiceClient service, AuthorisationService authService) {
        this.service = service;
        this.authService = authService;
    }

//    @PreAuthorize("hasAuthority('RESOURCE_001_HELLO')")
    @RequestMapping(value = "/hello", method = RequestMethod.POST)
    public String sayHello(@Valid @RequestBody Hello hello) {
        return this.service.sayHello(hello);
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

}
