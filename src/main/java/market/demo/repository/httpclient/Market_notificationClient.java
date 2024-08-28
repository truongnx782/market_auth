package market.demo.repository.httpclient;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.Map;

@FeignClient(name = "notification-service", url = "${app.services.notification}")
public interface Market_notificationClient {

    @PostMapping(value = "/notification/send-otp-register",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    void sendMailRegister(@RequestBody Map<String, Object> objectMap);

    @PostMapping(value = "/notification/send-otp-forgot-password",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    void sendMailForgotPassword(@RequestBody Map<String, Object> objectMap);

}
