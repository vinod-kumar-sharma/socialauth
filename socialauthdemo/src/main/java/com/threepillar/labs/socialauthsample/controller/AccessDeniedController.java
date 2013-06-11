package com.threepillar.labs.socialauthsample.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class AccessDeniedController {
	@RequestMapping(value = "/accessDeniedAction")
	public ModelAndView getRedirectURL(final HttpServletRequest request)
			throws Exception {
		ModelAndView mv = new ModelAndView();
		mv.setViewName("accessDenied");

		return mv;
	}
}
