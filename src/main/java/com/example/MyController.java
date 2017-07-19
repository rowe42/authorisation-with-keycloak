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
    @RequestMapping(value = "/method1", method = RequestMethod.GET)
    public String callMethod1(@Valid @RequestParam String permission) {
        return "executed Method 1";
    }

    @PreAuthorize("hasPermission(#permission, 'Entitlements')")
    @RequestMapping(value = "/method2", method = RequestMethod.GET)
    public String callMethod2(@Valid @RequestParam String permission) {
        return "executed Method 2";
    }

}
