package com.springsecurity.example.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/Spring-Security-Demo")
public class RestControllerEndPoints {
	@Autowired
	MessageSource messageSource;
	
	@RequestMapping(path = "/sayGM/internationalized", method = RequestMethod.GET)
	public String sayGoodMorning() {
		return getMessageForLocale("goodmorning.salutation") + getMessageForLocale("goodmorning.message");
	}

	private String getMessageForLocale(String key) {
		return messageSource.getMessage(key, new Object[] {" "} , LocaleContextHolder.getLocale());
	}
}