package org.sisvir.msvc.auth.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Collections;

@Service
public class UserService implements UserDetailsService {

    @Value("${URI_LOGIN}")
    private String uriLogin;

    @Autowired
    private WebClient.Builder client;

    private Logger log = LoggerFactory.getLogger(UserService.class);

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        try {

            org.sisvir.msvc.auth.models.User user = client
                    .build()
                    .get()
                    .uri(uriLogin, uri -> uri.queryParam("userName", userName).build())
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .bodyToMono(org.sisvir.msvc.auth.models.User.class)
                    .block();

            assert user != null;
            log.info("Usuario login: " + user.getId());
            log.info("Usuario nombre: " + user.getUserName());
            log.info("Password: " + user.getPassword());

            return new User(userName, user.getPassword(), true, true, true, true,
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
        } catch (RuntimeException e) {
            String error = "Error en el login, no existe el usuario " + userName +
                    " en el sistema";
            log.error(error);
            log.error(e.getMessage());
            throw new UsernameNotFoundException(error);
        }
    }
}
