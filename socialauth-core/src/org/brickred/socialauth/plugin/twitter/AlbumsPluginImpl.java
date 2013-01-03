/*
 ===========================================================================
 Copyright (c) 2012 3PillarGlobal

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sub-license, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
 ===========================================================================

 */
package org.brickred.socialauth.plugin.twitter;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.brickred.socialauth.Album;
import org.brickred.socialauth.Photo;
import org.brickred.socialauth.plugin.AlbumsPlugin;
import org.brickred.socialauth.util.Constants;
import org.brickred.socialauth.util.ProviderSupport;
import org.brickred.socialauth.util.Response;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Album Plugin implementation for Twitter
 * 
 * @author tarun.nagpal
 * 
 */
public class AlbumsPluginImpl implements AlbumsPlugin, Serializable {

	private static final long serialVersionUID = -4810906169491380470L;
	private static final String FEED_URL = "https://api.twitter.com/1.1/statuses/home_timeline.json?include_entities=true&count=100";
	private final Log LOG = LogFactory.getLog(this.getClass());
	private static HashMap<String, List<String>> photo_data = new HashMap<String, List<String>>();

	private ProviderSupport providerSupport;

	public AlbumsPluginImpl(final ProviderSupport providerSupport) {
		this.providerSupport = providerSupport;
	}

	@Override
	public List<Album> getAlbums() throws Exception {
		Response response = null;
		List<Album> albums = new ArrayList<Album>();
		LOG.info("Getting feeds from URL : " + FEED_URL);

		response = providerSupport.api(FEED_URL);
		String respStr = response.getResponseBodyAsString(Constants.ENCODING);
		LOG.debug("Feeds json string :: " + respStr);
		JSONArray jarr = new JSONArray(respStr);
		LOG.debug("Feeds count :: " + jarr.length());

		for (int i = 0; i < jarr.length(); i++) {
			Album album = new Album();
			JSONObject jobj = jarr.getJSONObject(i);

			if (jobj.has("user")) {
				JSONObject userObj = jobj.getJSONObject("user");

				if (jobj.has("entities")) {
					JSONObject entitiesObj = jobj.getJSONObject("entities");
					if (entitiesObj.has("media")) {
						JSONObject mediaObj = entitiesObj.getJSONArray("media")
								.getJSONObject(0);
						if (mediaObj.has("type")
								&& mediaObj.getString("type").equalsIgnoreCase(
										"photo")) {
							if (userObj.has("name")
									&& mediaObj.has("media_url")) {
								List<String> photos = photo_data.get(userObj
										.getString("name"));
								if (photos == null) {
									photos = new ArrayList<String>();
									photo_data.put(userObj.getString("name"),
											photos);

									album.setName(userObj.getString("name"));
									album.setCoverPhoto(userObj
											.getString("profile_image_url"));
									albums.add(album);
								}
								photos.add(mediaObj.getString("media_url"));
							}
						}
					}
				}
			}
		}

		for (Album album : albums) {
			List<Photo> photos = getAlbumPhotos(album.getName());
			album.setPhotos(photos);
			album.setPhotosCount(photos.size());
		}
		return albums;
	}

	private List<Photo> getAlbumPhotos(final String id) throws Exception {
		List<String> photo_list = photo_data.get(id);
		List<Photo> photos = new ArrayList<Photo>();
		for (String photoURL : photo_list) {
			Photo photo = new Photo();
			photo.setThumbImage(photoURL + ":thumb");
			photo.setSmallImage(photoURL + ":small");
			photo.setMediumImage(photoURL);
			photo.setLargeImage(photoURL + ":large");
			photos.add(photo);
		}
		return photos;
	}

	@Override
	public ProviderSupport getProviderSupport() {
		return providerSupport;
	}

	@Override
	public void setProviderSupport(final ProviderSupport providerSupport) {
		this.providerSupport = providerSupport;
	}
}
