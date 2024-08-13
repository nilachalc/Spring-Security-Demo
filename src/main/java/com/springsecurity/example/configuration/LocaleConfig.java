package com.springsecurity.example.configuration;

import java.util.Locale;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;

@Configuration
public class LocaleConfig {
	// While using the AcceptHeaderLocaleResolver, the caller must have to send the "Accept-Language" header property with the required locale as the value.
	@Bean
	public LocaleResolver localResolver() {
		AcceptHeaderLocaleResolver resolver = new AcceptHeaderLocaleResolver();
		resolver.setDefaultLocale(Locale.US);
		return resolver;
	}		
	
	//This is Plain Spring application configuration. We can replace the below bean by adding 1 line in application.properties
	//file for Spring Boot Application.
	//@Bean
	//public ResourceBundleMessageSource messageSource() {
	//	ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
	//	messageSource.setBasename("message");
	//	return messageSource;
	//}
}
