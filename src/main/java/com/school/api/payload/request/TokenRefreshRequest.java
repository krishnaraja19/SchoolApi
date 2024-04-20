package com.school.api.payload.request;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class TokenRefreshRequest {
    @NotBlank
    private String refreshToken;

}
