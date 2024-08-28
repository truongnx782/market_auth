package market.demo.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserDTO {
    private Long id;
    private String userCode;
    private String username;
    private String password;
    private String fullName;
    private String phoneNumber;
    private int status;
    private Long roleId;
}
