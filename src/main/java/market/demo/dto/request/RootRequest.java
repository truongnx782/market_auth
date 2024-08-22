package market.demo.dto.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RootRequest {
    public String sub;
    public String name;
    public String given_name;
    public String family_name;
    public String picture;
    public String email;
    public boolean email_verified;
    public String hd;
}
