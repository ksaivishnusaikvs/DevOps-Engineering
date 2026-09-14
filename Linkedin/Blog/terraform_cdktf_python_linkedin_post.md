# Terraform + CDKTF: AWS Infrastructure Using Python

I recently tried deploying an AWS S3 bucket using **Python + CDKTF** instead of Terraform HCL.

The plan was simple:

- Create an S3 bucket
- Enable versioning
- Add encryption
- Block public access
- Add tags

During the setup, I faced an issue with Python.

I first tried using my normal/system Python environment, but it didn't work.

So I created a virtual environment (venv) and installed the required packages.

**System Python → Didn't work**  
**Python venv → Worked**

After that, I tested the code and ran:

```bash
cdktf synth
cdktf diff
cdktf deploy
```

Everything worked, and the S3 bucket was created successfully.

The main thing I learned was simple: sometimes the issue is with the environment, not the infrastructure code.

Have you faced a similar issue while using Python + CDKTF?

How did you fix it?

**Blog:** https://lnkd.in/d3yJ8P8e

**GitHub:** https://github.com/ksaivishnusaikvs/DevOps-Engineering/tree/main/Linkedin

#AWS #Terraform #CDKTF #Python #DevOps #InfrastructureAsCode
