package com.auth.actions;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
import org.apache.struts.upload.FormFile;
import org.brickred.socialauth.AuthProvider;
import org.brickred.socialauth.SocialAuthManager;
import org.brickred.socialauth.util.Constants;
import org.brickred.socialauth.util.Response;

import com.auth.form.AuthForm;

public class SocialAuthUploadPhotoAction extends Action {

	final Log LOG = LogFactory.getLog(SocialAuthUploadPhotoAction.class);

	@Override
	public ActionForward execute(final ActionMapping mapping,
			final ActionForm form, final HttpServletRequest request,
			final HttpServletResponse response) throws Exception {
		LOG.info("Uploading Image");
		AuthForm authForm = (AuthForm) form;
		SocialAuthManager manager = authForm.getSocialAuthManager();
		AuthProvider provider = null;
		if (manager != null) {
			provider = manager.getCurrentAuthProvider();
		}
		if (provider != null) {
			try {
				FormFile file = authForm.getImageFile();
				String message = authForm.getMessage();
				Response res = provider.uploadImage(message,
						file.getFileName(), file.getInputStream());
				LOG.debug("Image Upload Response:: "
						+ res.getResponseBodyAsString(Constants.ENCODING));
				authForm.setMessage(null);
				authForm.setImageFile(null);
				if (res.getStatus() == 200) {
					request.setAttribute("Message",
							"Image Uploaded successfully");
					return mapping.findForward("success");
				} else {
					request.setAttribute("Message",
							"Getting error " + res.getStatus());
					return mapping.findForward("success");
				}
			} catch (Exception e) {
				request.setAttribute("Message", e.getMessage());
				LOG.error(e.getMessage());
			}
		}
		LOG.info("Error while uploading Image");
		request.setAttribute("Message", "Error in uploading image");
		return mapping.findForward("success");
	}
}
