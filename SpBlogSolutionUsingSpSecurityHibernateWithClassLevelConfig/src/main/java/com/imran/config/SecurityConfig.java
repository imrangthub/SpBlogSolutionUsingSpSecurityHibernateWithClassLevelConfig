package com.imran.config;



import javax.sql.DataSource;

import org.apache.commons.dbcp2.BasicDataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.*;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
@PropertySource("classpath:db.properties")
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	
	  @Autowired
	  private Environment env;
	
	 public DataSource getDataSource() {
	        DriverManagerDataSource dataSource = new DriverManagerDataSource();	
		    dataSource.setDriverClassName(env.getProperty("db.driver"));
		    dataSource.setUrl(env.getProperty("db.url"));
		    dataSource.setUsername(env.getProperty("db.username"));
		    dataSource.setPassword(env.getProperty("db.password"));
		    return dataSource;
		  }
	

/*    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .inMemoryAuthentication().passwordEncoder(passwordEncoder())
                .withUser("imran").password("123456").roles("ADMIN");
    }*/
	 
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication().dataSource(getDataSource())
                .passwordEncoder(passwordEncoder())
                .usersByUsernameQuery("select email, password, active from user where email= ?")
                .authoritiesByUsernameQuery("select u.email, r.role from user u inner join user_role ur on(u.id=ur.user_id) inner join role r on(ur.role_id=r.id) where u.email=?");
    }
    
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
    
    @Override
    public void configure(WebSecurity web) throws Exception {
        web
            .ignoring()
                .antMatchers("/resources/**");
    }

	@Override
	protected void configure(HttpSecurity http) throws Exception {

	    http
	        .authorizeRequests()
	            .antMatchers("/").permitAll()
	            .antMatchers("/post/**").hasRole("ADMIN")                                      
				.antMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')") 
	            .and()
	        .formLogin()
		        .loginPage("/auth/login")
	            .permitAll()
	            .failureUrl("/auth/login")
                .usernameParameter("email")
                .passwordParameter("password")
	             .and()    
	        .logout()
	            .deleteCookies("remove")
	            .logoutSuccessUrl("/")
	            .permitAll()
                .and()
                .csrf().disable();
	}
}
	