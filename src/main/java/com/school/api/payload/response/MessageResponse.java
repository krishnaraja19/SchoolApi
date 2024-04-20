package com.school.api.payload.response;

import lombok.*;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class MessageResponse {
    private String message;
}
