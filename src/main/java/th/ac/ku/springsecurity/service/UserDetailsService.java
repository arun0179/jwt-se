package th.ac.ku.springsecurity.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import th.ac.ku.springsecurity.model.User;
import th.ac.ku.springsecurity.repositories.UserRepository;

import java.util.Collection;
import java.util.Collections;

@Service
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).get();
        userRepository.findByUsername(username)
                        .orElseThrow(()  -> new UsernameNotFoundException("Username not found"));
        return new org.springframework.security.core.userdetails
                .User(user.getUsername(), user.getPassword()
                , true, true, true
                , true, getAuthorities("ROLE_USER"));
    }

    private Collection<? extends GrantedAuthority> getAuthorities(String role_user) {
        return Collections.singleton(new SimpleGrantedAuthority(role_user));
    }
}
