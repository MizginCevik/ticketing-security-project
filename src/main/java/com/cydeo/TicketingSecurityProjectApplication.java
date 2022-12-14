package com.cydeo;

import org.modelmapper.ModelMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class TicketingSecurityProjectApplication {

    public static void main(String[] args) {
        SpringApplication.run(TicketingSecurityProjectApplication.class, args);
    }

    @Bean
    public ModelMapper mapper() { // It's a class
        return new ModelMapper();
    }

    @Bean // to encode passwords
    public PasswordEncoder passwordEncoder() { // It's an interface
        return new BCryptPasswordEncoder(); // using one of the implementations
    } // it takes password and changes to encoded structure because it can not be saved as raw

}
