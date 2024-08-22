package market.demo.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.*;

import java.util.Date;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class InvalidatedToken {
    @Id
    @Column(name = "Id", nullable = false)
    private String id;

    @Column(name = "ExpiryTime", nullable = false)
    private Date expiryTime;
}
