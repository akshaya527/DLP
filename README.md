# DLP
Data Leakage Prevention (DLP) safeguards sensitive data from unauthorized access, transfer, or exposure. It uses policies, encryption, and monitoring to detect and block leaks across devices, networks, and applications, ensuring compliance and protecting confidential information from misuse.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
int isSensitive(const char *str)
{
    int digits = 0;
    const char *p = str;
    while (*p != '\0')
    {
        if (isdigit(*p)) digits++;
        p++;
    }
    return (digits == 16);
}
void maskData(char *str)
{
    char *p = str;
    while (*p != '\0')
    {
        if (isdigit(*p)) *p = '*';
        p++;
    }
}
int main()
{
    FILE *fp = fopen("data.txt", "r");
    FILE *log = fopen("log.txt", "w");
    if (!fp || !log)
    {
        printf("Error opening file.\n");
        return 1;
    }
    char *line = (char *)malloc(512 * sizeof(char));
    if (!line)
    {
        printf("Memory allocation failed.\n");
        return 1;
    }
    printf("Scanning file for sensitive data...\n");
    while (fgets(line, 512, fp))
    {
        if (isSensitive(line))
        {
            fprintf(log, "Sensitive data found: %s", line);
            maskData(line);
            printf("Masked: %s", line);
        }
    else
        {
            printf("Safe: %s", line);
        }
    }
    free(line);
    fclose(fp);
    fclose(log);
    printf("\nScan complete. Violations logged in log.txt\n");
    return 0;
}
