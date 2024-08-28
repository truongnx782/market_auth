package market.demo.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import market.demo.dto.UserDTO;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Builder
@Table(name = "Users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "Id")
    private Long id;

    @Column(name = "UserCode")
    private String userCode;

    @Column(name = "Username",nullable = false)
    private String username;

    @Column(name = "Password",nullable = false)
    private String password;

    @Column(name = "FullName")
    private String fullName;

    @Column(name = "PhoneNumber")
    private String phoneNumber;

    @Column(name = "Status",nullable = false)
    private int status;

    @Column(name = "RoleId", nullable = false)
    private Long roleId;

    public  static UserDTO toDTO(User user){
        return UserDTO.builder()
                .id(user.getId())
                .userCode(user.getUserCode())
                .fullName(user.getFullName())
                .phoneNumber(user.getPhoneNumber())
                .status(user.getStatus())
                .roleId(user.getRoleId())
                .build();
    }
}
