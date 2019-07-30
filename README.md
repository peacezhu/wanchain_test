### Here are my questions,plwase read them
My contract is in contracts directory，My deployment script is in deploy directory. Here is my deployment process, which includes successful and failed deployments
#### First I don't remove any methods to deploy,failed
![](picture/first.png)

#### second I  remove cooperativeSettle, userCloseChannel, updateProofAndSettleChannel and settleChannel functions.then i redeploy,success
![](picture/2.png)
![](picture/second.png)

#### third i open settleChannel function,i failed
![](picture/3.1.png)
![](picture/3.png)

#### fourth i remove content of settleChannel,i success
![](picture/4.1.png)
![](picture/4.png)

#### fifth i open cooperativeSettle function and remove it's content,i failed
![](picture/5.1.png)

