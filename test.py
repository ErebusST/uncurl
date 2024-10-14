# -*- coding: utf-8 -*-

"""


@author: ErebusST
@date: 2024/10/12 11:56
"""
from uncurl import parse_context

curl_string = """
curl -H "Host: j1.pupuapi.com" -H "product_main_picture_ab_4: 3" -H "product_main_picture_ab_2: 0" -H "pp-userid: 375031e7-a192-4d50-83ec-270ba8166563" -H "my_often_buy_banner_ab: 10" -H "product_main_picture_ab_3: 0" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIiLCJhdWQiOiJodHRwczovL3VjLnB1cHVhcGkuY29tIiwiaXNfbm90X25vdmljZSI6IjAiLCJpc3MiOiJodHRwczovL3VjLnB1cHVhcGkuY29tIiwiZ2l2ZW5fbmFtZSI6IuWLpOWKs-eahOilv-afmiIsImV4cCI6MTcyODcwODk1MCwidmVyc2lvbiI6IjIuMCIsImp0aSI6IjM3NTAzMWU3LWExOTItNGQ1MC04M2VjLTI3MGJhODE2NjU2MyJ9.Nue2pOLZU9_0rbm7M9MifvN3tOF3saynyoG_UkA5BMI" -H "sales_specifications_ab: 2" -H "spu_shopping_guide_link_ab: 0" -H "sign-v2: 7d5706ccaa9c577d265ac3163b30945d" -H "product_main_picture_ab_5: 4" -H "chart_ab: 4" -H "pp-version: 2023026310" -H "label_assembly_ab: 1" -H "is_show_classification_word: 1" -H "pp-seqid: TLb3yI7xKd8ovCyFzpSMWr6qalO55R/nkBZFyDHZuE0=" -H "seal-v2: {\"a\":\"4f9556d2fda7ceddc7407843182876edy0zZL2Qs\",\"b\":\"rNuuakPM\",\"c\":\"fuaWLszv\",\"d\":\"u5VBCg2L\",\"f\":\"rHHPu4nN+Kqs0u7xpTtU4Q2x7Yo5AZi7M6/Y6zT7/8JAzrjUi+HYiOiuSlmifJ6nZHdd044K8DAuYghLFxS2scOJSM6Wq3+puEjgSPxwKYU\"}" -H "user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 MicroMessenger/6.8.0(0x16080000) NetType/WIFI MiniProgramEnv/Mac MacWechat/WMPF XWEB/30515" -H "open-id: oMwzt0AxchL38F4lPhf5ehtG0hy0" -H "pp-os: 0" -H "Accept: application/json" -H "pp-placeid: c04270c9-26ad-4edb-8389-8f51a3d1a824" -H "timestamp: 1728701459128" -H "shopping_car_hint_banner_module: 0" -H "xweb_xhr: 1" -H "unit_price_ab: 1" -H "pp-suid: e3cefc3a-c806-4dc6-80b5-63ea6d762f82" -H "invalid_product_ab: 1" -H "Content-Type: application/json" -H "pp_store_city_zip: 440300" -H "pp_storeid: d4859c8c-b95c-4820-a13d-0a68f8654c11" -H "referer: https://servicewechat.com/wx122ef876a7132eb4/413/page-frame.html" -H "Sec-Fetch-Site: cross-site" -H "Sec-Fetch-Mode: cors" -H "Sec-Fetch-Dest: empty" -H "Accept-Language: zh-CN,zh" --data-binary "{\"app_id\":1,\"app_info\":{\"platform\":\"wx_mac\",\"app_version\":\"  4.5.9\"}}" --compressed "https://j1.pupuapi.com/client/app_resource/abtest/abtest_v1"
"""

# curl_string = """
# curl -H "Host: api.m.jd.com" -H "Cookie: mba_muid=1707186817452597953066; 3AB9D23F7A4B3C9B=XBRE6EL2UYTPF5UBFZXUKDRIN4SSQLNWWG5WVJMKMW5MONK7VSCIS47A5SXHSMWCLRIQ5U4QFFFHSWH6VKCQA542KI; shshshfpa=f3d16022-bca5-f8e1-a97a-dc69d9db6168-1707186834; shshshfpx=f3d16022-bca5-f8e1-a97a-dc69d9db6168-1707186834; jcap_dvzw_fp=K7TBZIN706MLj9MNe9FPK3Ub9AaDRfiov5gkJI0RYzgSzutq0rmVVH9psQG7Fm3Q96Q5ELYz2RDCYJZ7a5XhgQ==; whwswswws=; cart_uuid=0637f49a3cdd6512; PDJ_H5_PIN=JD_10b5fb9cb0567000; __jdv=122270672%7Cdirect%7C-%7Cnone%7C-%7C1728266920325; shshshfpb=BApXS8iIOZfdAJ84yTuIWVRuztR5iHdCyBkVZbxt_9xJ1Mi-h3IO2; TrackerID=s_jifUDdM3RhOzokjQVHE_aZ9TpdZAvTO3eN8h_MZ5SQ45Rh409qK_wF2gC77nuSYmDGsY_5zsWcXwkzR2t9J_aevuJ7iKe7VCu_X0rBeB0HvESsb5kVFHjfknmJu2jZ; pt_key=AAJnA5iyADBI95rK365_Nfi2SORYZB5H8RTzE_sbAP22YpcWiBgAS9RXJjOdsYoyYpwOSCPkOx0; pt_pin=ligai1018; pt_token=hk58qgzh; pwdt_id=ligai1018; sfstoken=tk01maf7d1b96a8sMSsyeDF4MSsy9IwsL+lhp9sAmkFZ6NDBLOHLE/iRtHTAw6u3Rjzmx2SyJ4yb7U27WYMa0HT+pCIO; deviceid_pdj_jd=H50d4c64e5-2e73-4c9b-8a1c-a447d6f6b43a; o2o_m_h5_sid=cf071e64-8ca9-4029-be60-3b046685b9a3; __jda=122270672.1707186817452597953066.1707186817.1728287617.1728613198.60; __jdc=122270672; 3AB9D23F7A4B3CSS=jdd03XBRE6EL2UYTPF5UBFZXUKDRIN4SSQLNWWG5WVJMKMW5MONK7VSCIS47A5SXHSMWCLRIQ5U4QFFFHSWH6VKCQA542KIAAAAMSPFQC6MQAAAAAD4PMWSMFC2HRPQX; mba_sid=172861319800357572133616721.7; __jd_ref_cls=log_name; __jdb=122270672.8.1707186817452597953066|60.1728613198" -H "sec-ch-ua: \"Chromium\";v=\"118\", \"Microsoft Edge\";v=\"118\", \"Not=A?Brand\";v=\"99\"" -H "sec-ch-ua-platform: \"Android\"" -H "sec-ch-ua-mobile: ?1" -H "user-agent: Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Mobile Safari/537.36 Edg/118.0.2088.41" -H "content-type: application/x-www-form-urlencoded" -H "accept: application/json, text/plain, */*" -H "x-requested-with: XMLHttpRequest" -H "x-rp-client: h5_1.0.0" -H "x-referer-page: https://daojia.jd.com/html/index/goodsDetails" -H "origin: https://daojia.jd.com" -H "sec-fetch-site: same-site" -H "sec-fetch-mode: cors" -H "sec-fetch-dest: empty" -H "referer: https://daojia.jd.com/" -H "accept-language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6" --data-binary "client=H5&appName=paidaojia&partner=&appVersion=8.41.0&useColor=true&useH5Color=true&colorApi=dj_product_detailV6_0&functionId=dj_product_detailV6_0&body=%7B%22skuId%22%3A%222134461037%22%2C%22storeId%22%3A%2212470549%22%2C%22orgCode%22%3A%22324234%22%2C%22longitude%22%3A116.48059%2C%22latitude%22%3A40.007217%2C%22type%22%3A2%2C%22treatyType%22%3A0%2C%22brand%22%3A%22%22%2C%22deviceModel%22%3A%22%22%2C%22buyNum%22%3A1%2C%22channel%22%3A%22%22%2C%22pageSource%22%3A%22productDetail%22%2C%22ctp%22%3A%22goodsinfo%22%2C%22refPar%22%3A%22%22%7D&signId=7d2d8&pageId=1aeebb1ede6daf519382c19106bf675d&lng=116.48059&lat=40.007217&city_id=1&poi=CLASS%28%E6%9E%9C%E5%B2%AD%E9%87%8C%29&jda=122270672.1707186817452597953066.1707186817.1728287617.1728613198.60&globalPlat=2&uuid=H50d4c64e5-2e73-4c9b-8a1c-a447d6f6b43a&traceId=H50d4c64e5-2e73-4c9b-8a1c-a447d6f6b43a1728613322462&ext=%7B%22jd_deviceId%22%3A%22H50d4c64e5-2e73-4c9b-8a1c-a447d6f6b43a%22%7D&avifSupport=0&appid=JDReactDaoJiaH5&t=1728613322463&loginType=12&source=H5&clientVersion=8.41.0&x-api-eid-token=jdd03XBRE6EL2UYTPF5UBFZXUKDRIN4SSQLNWWG5WVJMKMW5MONK7VSCIS47A5SXHSMWCLRIQ5U4QFFFHSWH6VKCQA542KIAAAAMSPFQC6MQAAAAAD4PMWSMFC2HRPQX&h5st=20241011102202476%3Brrxkbs2od1crrc25%3B7d2d8%3Btk03w9bba1c1518nCY9IOllSsebbBgRR1cIZ6tZCy9TBtfY4Ywp2NtKH1UHixKEHSP0KmHT1GcDGmHmWti_SGnEIzgyV%3B412150867ca28f104dce2acbd35a1b88%3B4.8%3B1728613322476%3BTKmWZt2Ome0KoWzO2uzOlCv_0WUOMm0OhOj_kNf_lGg7kKv_r1v6kNUOcOU6wNUO2uWLeW0I0eg_zNUO2uWL0_j_kyz9zVTId6D_i6jKgGz_19gKk6z_yRDJdGDK1NAK0W0I0WvFq5w_x5vO2W0UqOUJk6D_0Bw_xNQJi2z_fSz9gGwKfOz_iKQKdOA9jWzJhOUOcOk619v71JwO2W0UqO0Ko2zLi_f-xlA8wZBJuNUOcO050WUOMm0OH9BEDxTFm2jG01vO2uzOpZQ9oRw60WUOMm0OkKz7t5xO2uzOwVvO2W0UqiPO2uWK2uzOeCv_0WUO2W0UqO0O2uzOfCv_0WUO2W0UqSDK2uzOgCv_0WUO2W0UqWTOcOEJhNwO2WUO2uWLmW0I0GD50NUO2WUOMmUKiW0I0KD50NUO2WUOMmEKpW0I0OD50NUO2WUOMm0OdeEKoWzO2uzOlCv_0WUO2W0UqWTOcOk8fNUO2WUOMmUK2uzOjlwO2WUO2uWLmW0I0mwO2WUO2uWLmW0I0Gg50WUO2W0UbV0I0Gw7xFP4xNUO2uWLZVUOMOUIlWDKtRg9tlwO2uzOlWvO2WUO2um42uzOmVvO2W0UqO0DeCDGEhiLylA8hNSOhWk6h1-9IVkIme0J2GA8nNP9oRSOb2-5oxQD0W0I0SA5jNUO2um4%3Bb0e2c618b904a16b8500a033a5d362a5&cthr=1" --compressed "https://api.m.jd.com/client.action?appid=JDReactDaoJiaH5&functionId=dj_product_detailV6_0"
# """


# curl_string = """
# curl 'https://api.m.jd.com/client.action?appid=JDReactDaoJiaH5&functionId=dj_product_detailV6_0' \   -H 'accept: application/json, text/plain, */*' \   -H 'accept-language: en,zh-CN;q=0.9,zh;q=0.8' \   -H 'cache-control: no-cache' \   -H 'content-type: application/x-www-form-urlencoded' \   -H 'cookie: __jdu=16684845364291820856815; shshshfpa=51aa8768-5600-abab-8b8a-a987fc1c2dbb-1668484539; pinId=mDVof1qneR6dGQlAZb67Xw; shshshfpx=51aa8768-5600-abab-8b8a-a987fc1c2dbb-1668484539; jcap_dvzw_fp=VYKeZRe2kI1gKBa4__tvNUzQ5NC0sXKfABOgAv3uDxz_DfmfcurdlX9XettEmlDtkva5at23TA3yYJXXQZ-72A==; whwswswws=; b_webp=1; b_avif=1; b_dw=430; b_dh=932; b_dpr=3; TrackID=1c4nYH7bzITPkLC7BLoLTEIWiVHIC4zHo5YSwYuQCyQVohiETImQiwAS_OuurkSsdScuLvFDoKvqC_bn5Q-OmkWX0VXj-CeM3tx2X7eBLe8CMY7LYCeDYW7dNp1qswPBA; light_key=AASBKE7rOxgWQziEhC_QY6yayNeXraGDqk9jg_WkB9X_41iCEk092KBkvEpDKsRPcYczpQsq; 3AB9D23F7A4B3C9B=RCYSNZ6A54XEBM5V2MWYAM6GXIIOA2MJ4KXKVLT4ATNVLY4NPY6OE5RLNEEJJGP2GAXTAJ6PGJUBUCOQROW4QNB2CY; mba_muid=16684845364291820856815; PDJ_H5_PIN=JD_1064d68d4ba4a000; cart_uuid=939381fa827b3648; __jdc=181111935; __jdv=181111935%7Cwww.jddj.com%7C-%7Creferral%7C-%7C1728449345693; shshshfpb=BApXSHeiWbPdAXCl4pEdFHzlDwPBH2pxhByoJQhZX9xJ1MmGu2oO2; TrackerID=8KEcTZcHYnwKLy_U3qwV0qOoc9mAHNPUVT37_aQAHZhMAv4XawA3wPv6471iEPeWz1SdHVByE4aThZ36YkS-yNq5cU-PEpCi4blgTYVkn8jlEurOKMAxut0gLVrLWwj2KGGn3Nzg6_uYX9L8p5M8fQ; pt_key=AAJnBgwSADB5h-zBT2saFkwY4Wno6ZVh_DZVjVL1oZbxdPj1hC3DgrpdaDU_dqYRrIsP2wA6_7s; pt_pin=jd_DMjGhiUozayR; pt_token=a5g2sge8; pwdt_id=jd_DMjGhiUozayR; sfstoken=tk01m8cbd1baaa8sMXgzKzF4Mnh5j3DcGWQ0d84DQ6iM9b6a2CVJv7r1V9jvmE4sWmKrYVWFu6mveqRbwl+6j+w4JdUT; qid_uid=226a3c5a-fa54-4b7c-b5b7-ddc0ddea9c0f; qid_fs=1728449556491; qid_ls=1728449556491; qid_ts=1728449556499; qid_vis=1; deviceid_pdj_jd=H53fa779c8-d339-46c9-873d-cd9f9946ef58; o2o_m_h5_sid=4e2b1c76-1e2e-4363-bfa7-45a527d8fd05; __jda=181111935.16684845364291820856815.1668484536.1728617049.1728720627.201; 3AB9D23F7A4B3CSS=jdd03RCYSNZ6A54XEBM5V2MWYAM6GXIIOA2MJ4KXKVLT4ATNVLY4NPY6OE5RLNEEJJGP2GAXTAJ6PGJUBUCOQROW4QNB2CYAAAAMSP7DWTOAAAAAADKK5QXKDZREZD4X; _gia_d=1; __jdb=181111935.6.16684845364291820856815|201.1728720627; mba_sid=17287206271955976212717796341.11' \   -H 'origin: https://daojia.jd.com' \   -H 'pragma: no-cache' \   -H 'priority: u=1, i' \   -H 'referer: https://daojia.jd.com/' \   -H 'sec-fetch-dest: empty' \   -H 'sec-fetch-mode: cors' \   -H 'sec-fetch-site: same-site' \   -H 'user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1' \   -H 'x-referer-page: https://daojia.jd.com/html/index/goodsDetails' \   -H 'x-requested-with: XMLHttpRequest' \   -H 'x-rp-client: h5_1.0.0' \   --data-raw 'client=H5&appName=paidaojia&partner=&appVersion=8.41.0&useColor=true&useH5Color=true&colorApi=dj_product_detailV6_0&functionId=dj_product_detailV6_0&body=%7B%22skuId%22%3A%222104457147%22%2C%22storeId%22%3A%2211681855%22%2C%22orgCode%22%3A%22312194%22%2C%22longitude%22%3A116.4874%2C%22latitude%22%3A40.0094%2C%22type%22%3A2%2C%22treatyType%22%3A0%2C%22brand%22%3A%22%22%2C%22deviceModel%22%3A%22%22%2C%22buyNum%22%3A1%2C%22channel%22%3A%22%22%2C%22pageSource%22%3A%22productDetail%22%2C%22ctp%22%3A%22goodsinfo%22%2C%22refPar%22%3A%22%22%7D&signId=7d2d8&pageId=b32e040b87208d899493c71f89f2c2d9&lng=116.4874&lat=40.0094&city_id=1&poi=%E9%94%90%E5%88%9B%E5%9B%BD%E9%99%85%E4%B8%AD%E5%BF%83B%E5%BA%A7&jda=181111935.16684845364291820856815.1668484536.1728617049.1728720627.201&globalPlat=2&uuid=H53fa779c8-d339-46c9-873d-cd9f9946ef58&traceId=H53fa779c8-d339-46c9-873d-cd9f9946ef581728720702698&ext=%7B%22jd_deviceId%22%3A%22H53fa779c8-d339-46c9-873d-cd9f9946ef58%22%7D&avifSupport=1&appid=JDReactDaoJiaH5&t=1728720702698&loginType=12&source=H5&clientVersion=8.41.0&x-api-eid-token=jdd03RCYSNZ6A54XEBM5V2MWYAM6GXIIOA2MJ4KXKVLT4ATNVLY4NPY6OE5RLNEEJJGP2GAXTAJ6PGJUBUCOQROW4QNB2CYAAAAMSP7DWTOAAAAAADKK5QXKDZREZD4X&h5st=20241012161142726%3Bdcrk1o2dbxbsxb27%3B7d2d8%3Btk03wd0f31d4018nHUnfqgb1tfPf0OjxiVqikMKIMaVSms1e0-ki7i03_Alrs0pubKU0IhXkMBruZOtgkGqEtnG3wXd_%3B1b1ef5e0e3e7fad69912d4b60609a90e%3B4.8%3B1728720702726%3BTKmWZt2Ome0KoWzO2uzOlCv_0WUOMm0OfOz_eJv_eNQ9kaAKrNf_yNUOcOU6wNUO2uWLeW0I0eg_zNUO2uWL0_zKf_jKmGw_lGzKmGDIgSzKwVzKh2j_1BTJhyDIh_w90W0I0WvFq5w_x5vO2W0UqOUKkGDIjGTIhCj_xFQ9lKD9zJTKh6D_mGDK1Bj_yBzK1NUOcOk619v71JwO2W0UqO0Ko2zLi_f-xlA8wZBJuNUOcO050WUOMm0OAZiCqNg5x1BFd_yO2uzOpZQ9oRw60WUOMm0OqBQ5oxi_1hyO2uzOwVvO2W0UqiPO2uWK2uzOeCv_0WUO2W0UqO0O2uzOfCv_0WUO2W0UqSDK2uzOgCv_0WUO2W0UqWTOcOEJhNwO2WUO2uWLmW0I0GD50NUO2WUOMmEIjW0I0KD50NUO2WUOMmEKpW0I0OD50NUO2WUOMm0OdeEKoWzO2uzOlCv_0WUO2W0UqWTOcOk8fNUO2WUOMmUK2uzOjlwO2WUO2uWLmW0I0mwO2WUO2uWLmW0I0Gg50WUO2W0UbV0I0Gw7xFP4xNUO2uWLZVUOMO0CdRw4nBB8u5y8JFi-ytwO2uzOlWvO2WUO2um42uzOmVvO2W0UqOUA2KhD2KA_JVE9rxQ72_j-gSTODZSOxdg7uVB82CRCTVkIxdg7uVB80W0I0SA5jNUO2um4%3B71624cee0d03b49cb8227b4e8d73ca7d&cthr=1'
# """

curl_string = """
curl -X POST 'https://j1.pupuapi.com/client/app_resource/abtest/abtest_v1' -H 'User-Agent: Mozilla/5.0 (Linux; Android 10; MI 8 Build/QKQ1.190828.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/126.0.6478.188 Mobile Safari/537.36 XWEB/1260117 MMWEBSDK/20240301 MMWEBID/7990 MicroMessenger/8.0.48.2580(0x28003036) WeChat/arm64 Weixin NetType/WIFI Language/zh_CN ABI/arm64 MiniProgramEnv/android' -H 'Accept: application/json' -H 'Accept-Encoding: gzip,compress,br,deflate' -H 'Content-Type: application/json' -H 'charset: utf-8' -H 'seal-v2: {"a":"3c8e82b00a53a14d551f639d1b1a9a5eOVXcVVVQ","b":"E6av9b5I","c":"aLHQNfvy","d":"oTC7v7lw","f":"Uk3Oy2Su9RMrjJchCDeo861bLbNhqqezeP+B0zvwvzqdC5WpMtGm0xjKCrWbJ3wZbSJB7DKUcIH9r9cpEmlFwiNMTMKGMiZKofJx1Yh0rh4"}' -H 'pp-userid: c5871440-cd24-4518-a581-3b3af396adc5' -H 'label_assembly_ab: 1' -H 'open-id: oMwzt0N-mNnHm6JvLaJlz_elx86w' -H 'pp-os: 0' -H 'authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIiLCJhdWQiOiJodHRwczovL3VjLnB1cHVhcGkuY29tIiwiaXNfbm90X25vdmljZSI6IjEiLCJpc3MiOiJodHRwczovL3VjLnB1cHVhcGkuY29tIiwiZ2l2ZW5fbmFtZSI6IuWdpueOh-eahOe6ouavm-S4uSIsImV4cCI6MTcyODg5NjE2NCwidmVyc2lvbiI6IjIuMCIsImp0aSI6ImM1ODcxNDQwLWNkMjQtNDUxOC1hNTgxLTNiM2FmMzk2YWRjNSJ9.7jgt6u6SQ38wXUa2eXXY698KQXndEfUgrU5perDfcE8' -H 'pp-version: 2023026310' -H 'pp_store_city_zip: 350100' -H 'timestamp: 1728889268895' -H 'product_main_picture_ab_2: 0' -H 'pp-suid: b90c0864-9f61-46cf-8504-796def91f47a' -H 'is_show_classification_word: 1' -H 'pp-placeid: cf6a9354-5676-4f6a-b1ed-521915cd228d' -H 'product_main_picture_ab_5: 3' -H 'pp-seqid: ESzVhq1y6wB7HHVyzUuU8aRGQdbFrUrCmrmGick7XBc=' -H 'product_main_picture_ab_3: 1' -H 'product_main_picture_ab_4: 3' -H 'shopping_car_hint_banner_module: 1' -H 'my_often_buy_banner_ab: 10' -H 'pp_storeid: 6660fb8b-9a97-417c-ab47-1ef9c102e64a' -H 'invalid_product_ab: 1' -H 'unit_price_ab: 1' -H 'sign-v2: 146aaf6772721b704bcfb8782b40647e' -H 'chart_ab: 4' -H 'sales_specifications_ab: 2' -H 'Referer: https://servicewechat.com/wx122ef876a7132eb4/413/page-frame.html' -d '{"app_id":1,"app_info":{"platform":"wx_android","app_version":" 4.5.9"}}'
"""
data_json = parse_context(curl_string)
print(data_json)