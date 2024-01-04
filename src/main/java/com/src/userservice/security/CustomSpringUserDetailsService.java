package com.src.userservice.security;

import com.src.userservice.models.User;
import com.src.userservice.repositories.*;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.*;

import java.util.*;

@Service
public class CustomSpringUserDetailsService implements UserDetailsService {
    private UserRepository userRepository;

    public CustomSpringUserDetailsService(UserRepository userRepository){
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username)
                .orElseThrow(()->{throw new UsernameNotFoundException("UserName not found. "+username);});
        return new CustomUserDetails(user);
    }
}
