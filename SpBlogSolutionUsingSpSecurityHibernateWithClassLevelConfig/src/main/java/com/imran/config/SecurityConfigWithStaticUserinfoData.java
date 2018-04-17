//package com.imran.config;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.builders.WebSecurity;
//import org.springframework.security.config.annotation.web.configuration.*;
//import org.springframework.security.crypto.password.NoOpPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfigWithStaticUserinfoData extends WebSecurityConfigurerAdapter {
//
//    @Autowired
//    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
//        auth
//            .inMemoryAuthentication().passwordEncoder(passwordEncoder())
//                .withUser("imran").password("123456").roles("ADMIN");
//    }
//    
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return NoOpPasswordEncoder.getInstance();
//    }
//    
//    @Override
//    public void configure(WebSecurity web) throws Exception {
//        web
//            .ignoring()
//                .antMatchers("/resources/**");
//    }
//
//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
//
//	    http
//	        .authorizeRequests()
//	            .antMatchers("/").permitAll()
//	            .antMatchers("/post/**").hasRole("ADMIN")                                      
//				.antMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')") 
//	            .and()
//	        .formLogin()
//		        .loginPage("/auth/login")
//	            .permitAll()
//	            .failureUrl("/auth/login")
//                .usernameParameter("email")
//                .passwordParameter("password")
//	             .and()    
//	        .logout()
//	            .deleteCookies("remove")
//	            .logoutSuccessUrl("/")
//	            .permitAll()
//                .and()
//                .csrf().disable();
//	}
//}
//	