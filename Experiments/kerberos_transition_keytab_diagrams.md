# Kerberos transition keytab sequence diagrams

## Before rotation

```text
Client A                  AD / KDC                         Apache service
--------                  --------                         --------------
1. Has TGT
2. Requests service
   ticket for
   HTTP/linux-srv01  ---> 3. KDC issues service ticket
                              encrypted for service key
                              KVNO 4
                          <---
4. Caches service ticket
   (KVNO 4)

5. Sends cached service
   ticket to Apache   ----------------------------------------------->

                                                          6. Apache looks in
                                                             keytab
                                                          7. Finds KVNO 4 key
                                                          8. Decrypts ticket
                                                          9. Access succeeds
```

## Rotation happens

```text
Admin / Script            AD / KDC                         Apache service
--------------            --------                         --------------
10. Resets service
    account password ---> 11. AD current key becomes KVNO 5

12. Deploys transition
    keytab to Apache
    containing:
      - KVNO 4 key
      - KVNO 5 key
```

## Branch A: old cached ticket still works

```text
Client A                  AD / KDC                         Apache service
--------                  --------                         --------------
13. Still has old cached
    service ticket
    (KVNO 4)

14. Sends old cached
    ticket to Apache  ----------------------------------------------->

                                                          15. Apache checks
                                                              active keytab
                                                          16. Finds old KVNO 4
                                                              entry still present
                                                          17. Decrypts ticket
                                                          18. Access succeeds
```

## Branch B: fresh ticket also works

```text
Client B                  AD / KDC                         Apache service
--------                  --------                         --------------
19. Requests fresh
    service ticket   ---> 20. KDC issues new service ticket
                              using current key KVNO 5
                          <---

21. Sends fresh KVNO 5
    ticket to Apache  ----------------------------------------------->

                                                          22. Apache checks
                                                              active keytab
                                                          23. Finds KVNO 5 key
                                                          24. Decrypts ticket
                                                          25. Access succeeds
```

## Commit / cleanup

```text
Admin / Script                                          Apache service
--------------                                          --------------
26. Replaces transition keytab
    with current-only keytab
    containing only KVNO 5  ---------------------------> 27. Apache now has
                                                              only KVNO 5

28. Client with old KVNO 4
    cached ticket tries again -------------------------> 29. Apache cannot find
                                                              old key anymore
                                                          30. Decryption fails
                                                          31. Access fails

32. Client gets fresh ticket
    from KDC (KVNO 5)  --------------------------------> 33. Apache decrypts
                                                              with KVNO 5
                                                          34. Access succeeds
```

## Short mental model

```text
Old cached ticket works
only if
service still has old key locally.

Fresh new ticket works
only if
service has new current key locally.
```
