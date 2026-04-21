# Kerberos transition keytab sequence diagrams

## Before rotation

```text
Client A                  AD / KDC                         Apache service
--------                  --------                         --------------
1. Requests TGT      ---> 2. KDC issues TGT
                        <---
3. Has TGT
4. Requests service
   ticket for
   HTTP/linux-srv01  ---> 5. KDC issues service ticket
                              encrypted for service key
                              KVNO 4
                          <---
6. Caches service ticket
   (KVNO 4)

7. Sends cached service
   ticket to Apache   ----------------------------------------------->

                                                          8. Apache looks in
                                                             keytab
                                                          9. Finds KVNO 4 key
                                                          10. Decrypts ticket
                                                          11. Access succeeds
```

## Rotation happens

```text
Admin / Script            AD / KDC                         Apache service
--------------            --------                         --------------
12. Resets service
    account password ---> 13. AD current key becomes KVNO 5

14. Deploys transition
    keytab to Apache
    containing:
      - KVNO 4 key
      - KVNO 5 key
```

## Branch A: old cached ticket still works

```text
Client A                  AD / KDC                         Apache service
--------                  --------                         --------------
15. Still has old cached
    service ticket
    (KVNO 4)

16. Sends old cached
    ticket to Apache  ----------------------------------------------->

                                                          17. Apache checks
                                                              active keytab
                                                          18. Finds old KVNO 4
                                                              entry still present
                                                          19. Decrypts ticket
                                                          20. Access succeeds
```

## Branch B: fresh ticket also works

```text
Client B                  AD / KDC                         Apache service
--------                  --------                         --------------
21. Requests TGT     ---> 22. KDC issues TGT
                        <---
23. Has TGT
24. Requests fresh
    service ticket   ---> 25. KDC issues new service ticket
                              using current key KVNO 5
                          <---

26. Sends fresh KVNO 5
    ticket to Apache  ----------------------------------------------->

                                                          27. Apache checks
                                                              active keytab
                                                          28. Finds KVNO 5 key
                                                          29. Decrypts ticket
                                                          30. Access succeeds
```

## Commit / cleanup

```text
Admin / Script                                          Apache service
--------------                                          --------------
31. Replaces transition keytab
    with current-only keytab
    containing only KVNO 5  ---------------------------> 32. Apache now has
                                                              only KVNO 5

33. Client with old KVNO 4
    cached ticket tries again -------------------------> 34. Apache cannot find
                                                              old key anymore
                                                          35. Decryption fails
                                                          36. Access fails

37. Client gets fresh ticket
    from KDC (KVNO 5)  --------------------------------> 38. Apache decrypts
                                                              with KVNO 5
                                                          39. Access succeeds
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
