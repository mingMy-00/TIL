# ACID

ACID는 데이터베이스에서 **안전성**과 **데이터 일관성**을 보장해주는 4가지 원칙이다.

<br>

1. **Atomicity (원자성)**
- 원자성은 트랜잭션이 모두 성공하거나 전혀 실행되지 않음을 보장한다.
- 예를 들어 은행에서 계좌 이체를 할 때, A 계좌에서 돈을 빼고 B 계좌에 돈을 넣는 두 작업이 한 트랜잭션으로 묶여야한다. 만약 A에서 돈이 빠졌지만 B에 입금되지 않으면 데이터가 불일치하게 되기 때문에, 중간에 에러가 발생하면 **트랜잭션 전부를 롤백시켜 일관성을 유지**해야한다.

<br>

2. **Consistency (일관성)**
- 일관성은 트랜잭션이 시작되기 전과 완료된 후에 데이터베이스가 항상 유효한 상태에 있음을 보장
    
    ```
    💡 유효한 상태
    데이터베이스가 설정된 제약 조건을 준수하고, 비즈니스 규칙이나 논리적으로 맞는 데이터를 유지하고 있는 상태를 말한다.
    ```
    
- 이를 위해 데이터베이스에서 설정된 제약 조건 (외래 키, 유일성, 데이터 형식 등)이 트랜잭션 완료 후에도 모두 충족되어야 한다. 트랜잭션이 불일치 상태로 끝나려 한다면, 트랜잭션을 실패 처리하여 데이터 무결성을 유지한다.

<br>

3. **Isolation (고립성)**
- 고립성은 여러 트랜잭션이 동시에 실행될 때 서로 간섭하지 않도록 보장하는 것
- 예를 들어, 두 개의 트랜잭션이 동시에 하나의 계좌에서 돈을 인출하려고 할 때, 하나의 트랜잭션이 끝날 때까지 다른 트랜잭션은 그 계좌의 잔액을 수정할 수 없다.

<br>

4. **Durability (지속성)**
- 지속성은 트랜잭션이 성공적으로 커밋되면, 시스템 장애나 충돌이 발생해도 그 결과가 영구적으로 저장됨을 보장
- 이를 위해 데이터베이스는 트랜잭션이 완료될 때 디스크나 비휘발성 저장 장치에 데이터를 기록하고, 트랜잭션 로그 등을 사용해 장애 복구 시에도 데이터 무결성을 유지할 수 있게 한다.

<br>

ACID를 지키면 데이터베이스의 **안전성**과 **데이터 일관성**을 보장할 수 있다.