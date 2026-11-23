resource "aws_db_instance" "main" {
  identifier              = "secure-api"
  engine                  = "postgres"
  instance_class          = "db.t4g.medium"
  storage_encrypted       = true
  backup_retention_period = 14
  deletion_protection     = true
  copy_tags_to_snapshot   = true
}
